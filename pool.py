#!/usr/bin/env python
from __future__ import print_function
from gevent import monkey, spawn
monkey.patch_all()
from gevent.pool import Pool
from gevent.socket import wait_read
from gevent.server import StreamServer
from random import shuffle
import os
import sys
import ast
import math
import time
import re
import hashlib
import string
import argparse
import json
import logging as LOG
from collections import defaultdict

from Crypto.Hash import SHA

from common import *
import bismuth


class Abuse(object):
    ip_strikes = defaultdict(int)
    ip_blocked = defaultdict(int)

    @classmethod
    def tick(cls):
        """Maintain abuse mechanisms, preventing build-up of data"""
        now = time.time()
        remove_ips = set()
        for ip, block_until in cls.ip_blocked.items():
            if block_until < now:
                remove_ips.add(ip)
        for ip, strikes in cls.ip_strikes.items():
            if strikes == 0 and ip not in cls.ip_blocked:
                remove_ips.add(ip)
        for ip in remove_ips:
            cls.reset(IpPort(ip, None))

    @classmethod
    def strikes(cls, ip):
        return cls.ip_strikes.get(ip, 0)

    @classmethod
    def strike(cls, peer):
        ip = peer.ip
        if ip == '127.0.0.1':
            return False
        cls.ip_strikes[ip] += 1
        strikes = cls.ip_strikes[ip]
        if strikes >= STRIKE_COUNT:
            cls.ip_blocked[ip] = time.time() + (STRIKE_TIME * STRIKE_COUNT)
            LOG.warning('IP %r - Blocked (%d strikes)', ip, strikes)
            return True
        return False

    @classmethod
    def reset(cls, peer):
        ip = peer.ip
        if ip in cls.ip_blocked:
            del cls.ip_blocked[ip]
        if ip in cls.ip_strikes:
            del cls.ip_strikes[ip]

    @classmethod
    def blocked(cls, peer):
        ip = peer.ip
        strikes = cls.ip_strikes.get(ip, 0)
        blocked_until = cls.ip_blocked.get(ip, None)
        if blocked_until is not None:
            now = time.time()
            if blocked_until < now:
                cls.reset(peer)
                return False
        return strikes >= STRIKE_COUNT


# TODO: when there is no consensus, or we're behind ..
#   run server.stop_accepting or server.start_accepting
class Miners(object):
    def __init__(self, peers, bind=None, max_peers=1000):
        if bind is None:
            bind = ('127.0.0.1', POOL_PORT)
        elif isinstance(bind, str):
            bind = bind.split(':')
            bind[1] = int(bind[1])
        self.peers = peers
        self.pool = Pool(max_peers)
        self.server = StreamServer(tuple(bind), self._on_connect, spawn=self.pool)
        self.server.start()

    def on_found(self, result, miner):
        # Ensure that the work delivered is exactly what was requested
        valid = bismuth.verify(result.address, result.nonce, result.block, result.diff)
        if not valid:
            Abuse.strike(miner.sockaddr)
            if Abuse.blocked(miner.sockaddr):
                miner.close()
            LOG.error('Invalid block submitted! %r %r', result, miner.diff, valid)
            return False
        # The miner will not be punished for providing
        # training blocks which don't match the right
        # hash... but they won't be rewarded for the work
        return ResultsManager.on_result(result, miner)

    def stop(self):
        self.server.stop()
        self.pool.kill()

    def _on_connect(self, socket, address):
        peer = IpPort(*address)
        if Abuse.blocked(peer):
            LOG.debug('Miner %r - accept() blocked: abuse', address)
            socket.close()
            return
        client = MinerServer(socket, self)
        client.run()


# Don't allow client to submit same block twice
# Verify that clients don't submit each others blocks
# Verify that the block difficulty matches or is above that set by this code (the pool)
class MinerServer(ProtocolBase):
    def __init__(self, sock, manager):
        super(MinerServer, self).__init__(sock, manager)
        self._reward_address = None
        self._history = []
        self._diff = 37
        self._last_found = None

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    @property
    def diff(self):
        return self._diff

    @property
    def address(self):
        return self._reward_address

    def _tune(self):
        # Fine-tune the difficulty so the miner finds at least 1 block every N seconds
        # Use a rolling history of block find times to get the average difficulty
        hist_time = defaultdict(int)
        hist_count = defaultdict(int)
        for diff, duration in self._history:
            hist_time[diff] += duration
            hist_count[diff] += 1.0
        ideal_diff = self._diff
        best_time = 0
        for diff, total_time in hist_time.items():
            avg_time = total_time / hist_count[diff]
            if avg_time > best_time and avg_time < MINER_TUNE_GOAL:
                best_time = avg_time
                ideal_diff = diff
        if best_time > MINER_TUNE_GOAL:
            ideal_diff -= 1
        else:
            if self._last_found > (time.time() - MINER_TUNE_GOAL):
                ideal_diff += 0.5
        peers_diff = int(self.manager.peers.difficulty())
        our_height = ResultsManager.HEIGHTS.keys()
        our_height = (max(our_height) + 1) if len(our_height) else 37
        self._diff = min([our_height, sum([peers_diff, ideal_diff]) / 2])
        # Trim history
        if len(self._history) > MINER_TUNE_HISTORY:
            self._history = self._history[0 - MINER_TUNE_HISTORY:]

    def _cmd_sendsync(self):
        # They've mistaken us for a regular node, no a pool
        pass

    def _cmd_version(self):
        """
        Check client version string, and save their reward address
        """
        version = self._recv().split('.')
        rewards = self._recv()
        if version[0] != MINER_VERSION_ROOT:
            self._send('notok')
            return self.close()
        is_hex = all(c in string.hexdigits for c in rewards)
        if len(rewards) == 56 and is_hex:
            self._reward_address = rewards
        LOG.info('Client connected: version="%r" address="%r"', version, self._reward_address)
        self._send('ok')

    def _cmd_miner_fetch(self):
        # TODO: retrieve most appropriate data to work on...
        LOG.info('Miner %r - Fetch Job')
        peers = self.manager.peers
        consensus = peers.consensus()
        if len(consensus):
            self._send(int(self._diff), peers.identity.address, consensus[0][0][1])
        else:
            # Send training data when there is no consensus
            self._send(int(self._diff), peers.identity.address, os.urandom(28).encode('hex'))

    def _cmd_miner_exch(self):
        items = None
        try:
            items = (self._recv(), self._recv(), self._recv())
            result = MinerResult(float(items[0]), self.manager.peers.identity.address, items[1], items[2])
        except Exception as ex:
            LOG.exception("Miner %r - Rejecting Items: %r - %r", self.sockaddr, items, ex)
            Abuse.strike(self.sockaddr)
            return self._cmd_miner_fetch()  # wat u send, thafuq?
        if result:
            if self.manager.on_found(result, self):
                if self._last_found is not None:
                    mine_duration = time.time() - self._last_found
                    self._history.append((self._diff, mine_duration))
                self._last_found = time.time()
            # Finally, re-calculate the diff rate etc...
            self._tune()
        return self._cmd_miner_fetch()

    def _cmd_status(self):
        self._send(str(self.manager.status()))

    def run(self):
        try:
            while self.sock:
                try:
                    wait_read(self.sock.fileno(), timeout=10)
                except socket.timeout:
                    continue
                cmd_name = self._recv()
                if not cmd_name:
                    break
                cmd_func = getattr(self, '_cmd_' + cmd_name, None)
                if not cmd_func:
                    raise RuntimeError('Miner %r - Unknown CMD: %r' % (self.sockaddr, cmd_name))
                LOG.info("Miner %r - Invalid Command: %r", self.sockaddr, cmd_name)
                cmd_func()
        except Exception as ex:
            LOG.exception("Miner %r - Error running: %r", self.sockaddr, ex)
            Abuse.strike(self.sockaddr)
        finally:
            self.close()


class BismuthClient(ProtocolBase):
    def __init__(self, sock, manager):
        super(BismuthClient, self).__init__(sock, manager)
        toplist = manager.consensus()
        if len(toplist):
            toplist = toplist[0]
            self.blocks = list([
                (toplist[0][0], toplist[0][1], None)
            ])
        else:
            self.blocks = list([
                (98312, "8618dda7a8c5213ca56169d2459e62231c3fd834d60446f554195efb", None)
            ])
        self.blockheight = self.blocks[0][0]
        self.blockhash = self.blocks[0][1]
        self.their_blockheight = 0
        self.their_blockhash = ''
        self._diff = 37
        self.peers = None
        self._mempool = []

    @property
    def mempool(self):
        return self._mempool

    def status(self):
        if not self.sock:
            return "dead"
        if not self.synched:
            return "synching" + " (%d <- %d[%s])" % (self.their_blockheight, self.blockheight, self.blockhash[:10])
        return "active (%.2f diff)" % (self._diff,) + " (%d[%s])" % (self.blockheight, self.blockhash[:10])

    def submit_block(self, new_txns):
        self._send('block', str(new_txns))

    def getdiff(self):
        self._send("getdiff")
        new_diff = float(self._recv())
        if self.their_blockheight == self.blockheight:
            self._diff = new_diff
        return self._diff

    def pushpeers(self):
        shuffle(self.peers)
        self._send("peers", "\n".join(map(str, self.peers[:10])))

    def sync_mempool(self):
        self._send("mempool", '[]')
        self._mempool = ast.literal_eval(self._recv())

    def connect(self):
        try:
            self._send("version", PROTO_VERSION)
            data = self._recv()
            if data != "ok":
                raise RuntimeError("Peer %r - protocol mismatch: %r %r" % (self.sockaddr, data, PROTO_VERSION))
                return False
        except Exception as ex:
            Abuse.strike(self.sockaddr)
            LOG.warning("Peer %r - Connect/Hello error: %r", self.sockaddr, ex)
            return False
        LOG.info('Peer %r - Connected', self.sockaddr)
        return True

    def _cmd_nonewblk(self):
        self.getdiff()
        self.sync_mempool()

    def _cmd_getdiff(self):
        self._send("getdiff")
        try:
            self._diff = float(self._recv())
            print("Diff", self._diff)
        except ValueError:
            print("FAILS")
        return self._diff

    def _cmd_peers(self):
        subdata = self._recv()
        self.peers = re.findall("'([\d\.]+)', '([\d]+)'", subdata)

    def _cmd_blocksfnd(self):
        self._send("blockscf")
        block_list = ast.literal_eval(self._recv())
        block = None
        for transaction_list in block_list:
            # TODO: verify transactions
            self.blockhash = hashlib.sha224(str(transaction_list) + self.blockhash).hexdigest()
            self.blockheight += 1
            block = (self.blockheight, self.blockhash, transaction_list)
            self.blocks.append(block)
            if self.blockheight == self.their_blockheight:
                self.their_blockhash = self.blockhash
            if len(self.blocks) > 5:
                # Only keep latest 10 blocks
                self.blocks = self.blocks[-5:]
        if block:
            self.manager.block_add(block)
        # XXX: speed up initial sync... instead of at other ends leisure
        #      request more sync until our expected and their actual are the same
        if self.blockheight != self.their_blockheight:
            self._send("sendsync")

    def _cmd_blocknf(self):
        block_hash_delete = self._recv()
        print("Asked to delete block", block_hash_delete)
        self.blocks = filter(lambda x: x[1] != block_hash_delete, self.blocks)
        self.manager.block_remove(block_hash_delete)
        if block_hash_delete in (self.blockhash, self.their_blockhash):
            if len(self.blocks):
                print("Deleting block:", self.blocks, block_hash_delete, self.blockhash, self.their_blockhash)
                self.blockhash = self.blocks[-1][1]
                self.blockheight = self.blocks[-1][0]

    def _cmd_sync(self):
        self._send("blockheight", self.blockheight)
        their_blockheight = int(self._recv())
        LOG.info("Their blockheight: %r Our Blockheight %r", their_blockheight, self.blockheight)
        self.their_blockheight = their_blockheight
        if self.their_blockheight == self.blockheight:
            self.their_blockhash = self.blockhash
        update_me = (their_blockheight >= self.blockheight)
        if update_me:
            self._send(self.blockhash)
        else:
            self.their_blockhash = self._recv()
            if self.their_blockhash != self.blockhash:
                cut = 0
                for N, txn in enumerate(reversed(self.blocks)):
                    if txn[1] == self.their_blockhash:
                        self.blockheight = self.their_blockheight = txn[0]
                        self.blockhash = txn[1]
                        cut = N
                        break
                if cut:
                    self.blocks = self.blocks[:0 - cut]

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    @property
    def synched(self):
        return (self.blockheight == self.their_blockheight) and (self.blockhash == self.their_blockhash)

    def run(self):
        sync_interval = 10
        sync_last = time.time()
        while self.sock:
            try:
                wait_read(self.sock.fileno(), timeout=sync_interval)
            except socket.timeout:
                # After initial synching, send periodic sync requests
                now = time.time()
                if sync_last < (now - sync_interval):
                    self._send("sendsync")
                    sync_last = now

            cmd_name = self._recv()
            if not cmd_name:
                break
            cmd_func = getattr(self, '_cmd_' + cmd_name, None)

            if not cmd_func:
                LOG.warning('Peer %r - Unknown CMD: %r' % (self.sockaddr, cmd_name))
                self.close()
                return False

            LOG.info("Peer %r - Sent: %r", self.sockaddr, cmd_name)
            cmd_func()
        return True


class ResultsManager(object):
    HEIGHTS = dict()
    BLOCK = None
    HIGHEST = 0
    LOGHANDLE = None
    LOGFILENAME = None

    @classmethod
    def on_consensus(cls, consensus):
        if cls.BLOCK == consensus:
            return
        cls.HEIGHTS = dict()
        cls.BLOCK = consensus
        cls.HIGHEST = 0

        if cls.LOGHANDLE:
            cls.LOGHANDLE.flush()
            cls.LOGHANDLE.close()
            done_filename = 'data/done/%d.block' % (int(consensus[0]))
            if cls.LOGFILENAME is not None and not os.path.exists(done_filename):
                os.rename(cls.LOGFILENAME, done_filename)
            else:
                LOG.warning('Merging block logs: %r -> %r', cls.LOGFILENAME, done_filename)
                with open(done_filename, 'a') as handle_output:
                    with open(cls.LOGFILENAME, 'r') as handle_input:
                        while True:
                            data = handle_input.read(4096)
                            if not data:
                                break
                            handle_output.write(data)

        filename = 'data/audit/%d.block' % (int(consensus[0]))
        cls.LOGHANDLE = open(filename, 'a')
        cls.LOGFILENAME = filename
        LOG.warning('New consensus: %r', consensus)

    @classmethod
    def on_result(cls, result, miner):
        if not cls.BLOCK or result.block != cls.BLOCK[1]:
            # If no latest consensus block - ignore, it's training data
            return False
        if result.diff > cls.HIGHEST:
            cls.HIGHEST = result.diff
            cls.HEIGHTS[int(result.diff)] = result
            LOG.warning('New highest for %s: %d', result.block, result.diff)
        if cls.LOGHANDLE:
            cls.LOGHANDLE.write(json.dumps([
                time.time(), miner.address, int(result.diff), result.nonce
            ]) + "\n")
        return True

    @classmethod
    def sign_blocks(cls, identity, result, mempool):
        block_send = list()
        for dbdata in mempool:
            transaction = (
                str(dbdata[0]), str(dbdata[1][:56]), str(dbdata[2][:56]),
                '%.8f' % float(dbdata[3]), str(dbdata[4]), str(dbdata[5]), str(dbdata[6]),
                str(dbdata[7]))  # create tuple
            # print transaction
            block_send.append(transaction)  # append tuple to list for each run

        block_timestamp = '%.2f' % time.time()
        transaction_reward = (str(block_timestamp), str(result.address[:56]), str(result.address[:56]),
                              '%.8f' % float(0), "0", str(result.nonce))  # only this part is signed!

        transaction_hash = SHA.new(str(transaction_reward))
        signature_b64 = identity.sign(transaction_hash)

        block_send.append((str(block_timestamp), str(result.address[:56]), str(result.address[:56]), '%.8f' % float(0), str(signature_b64),
                           str(identity.public_key_hashed), "0", str(result.nonce)))  # mining reward tx
        return block_send


class PeerManager(object):
    def __init__(self, identity=None):
        if identity is None:
            identity = Identity()
        self.peers = dict()
        self.mempool = []
        self.identity = identity

    def status(self):
        active_peers = filter(lambda x: x.synched, self.peers)
        consensus = self.consensus()
        if consensus:
            consensus = consensus[0]
        return dict(
            peers=(len(active_peers), len(self.manager.peers)),
            diff=self.difficulty(),
            block=consensus,
        )

    def add(self, peer):
        assert isinstance(peer, IpPort)
        if peer not in self.peers and not Abuse.blocked(peer):
            return spawn(self._run, peer)

    def difficulty(self):
        values = [peer._diff for peer in self.peers.values() if peer.synched]
        if len(values):
            return sum(values) / float(len(values))
        return 37

    def block_add(self, block):
        self.mempool.append(block)
        if len(self.mempool) > (len(self.peers) + 1):
            shuffle(self.mempool)
            self.mempool = self.mempool[:len(self.peers)]

    def block_remove(self, block_hash):
        for block in self.mempool:
            if block[1] == block_hash:
                self.mempool.remove(block)
                break

    def stop(self):
        for peer in self.peers.values():
            peer.close()

    def consensus(self, blocks=None, update_top=False):
        """
        Highest block consensus information for all peers
        Returns tuple of:
          * Block Height
          * Number of Votes
          * Percentage of votes
        """
        if not blocks:
            blocks = [peer.blocks[-1] for peer in self.peers.values() if len(peer.blocks) and peer.synched]
        counts = defaultdict(int)
        heights = dict()
        for block in blocks:
            heights[block[1]] = block[0]
            counts[block[1]] += 1
        result = list()
        for block_hash, num in counts.items():
            block_height = heights[block_hash]
            row = ((block_height, block_hash), num, num / (len(blocks) / 100.0))
            result.append(row)
        results = sorted(result, lambda x, y: int(y[2] - x[2]))
        if len(results) and update_top:
            ResultsManager.on_consensus(results[0][0])
        return results

    def _run(self, peer, client=None):
        client = None
        sock = None
        if not client:
            try:
                sock = socket.create_connection(peer, timeout=CONNECT_TIMEOUT)
                sock.settimeout(None)
                client = BismuthClient(sock, self)
            except socket.error as ex:
                Abuse.strike(peer)
                LOG.info("Peer %r - Connect Error (%d strikes): %r",
                         peer, Abuse.strikes(peer), ex)
        try:
            if client:
                fail = False
                try:
                    if not client.connect():
                        fail = True
                    else:
                        self.peers[peer] = client
                except Exception as ex:
                    fail = True
                    Abuse.strike(peer)
                    LOG.info("Peer %r - Handshake error (%d strikes) - %r",
                             peer, Abuse.strikes(peer), ex)
                else:
                    Abuse.reset(peer)
                    client.run()
                if fail:
                    client.close()
                    client = None
        except socket.error as ex:
            LOG.warning('Peer %r - Socket Error: %r', peer, ex)
        except Exception as ex:
            LOG.exception("Peer %r - Run Error %r", peer, ex)
        finally:
            try:
                if client:
                    client.close()
                elif sock:
                    sock.close()
            except Exception:
                LOG.exception("While closing peer")
            if peer in self.peers:
                del self.peers[peer]


def read_peers(peers_file):
    # return []
    with open(peers_file, 'r') as handle:
        peers = [ast.literal_eval(row) for row in handle]
        shuffle(peers)
        return peers


def parse_args():
    parser = argparse.ArgumentParser(description='PooledBismuth Node')
    parser.add_argument('-v', '--verbose', action='store_const',
                        dest="loglevel", const=LOG.INFO,
                        help="Log informational messages")
    parser.add_argument('--debug', action='store_const', dest="loglevel",
                        const=LOG.DEBUG, default=LOG.WARNING,
                        help="Log debugging messages")
    parser.add_argument('--keyfile', help="Load/save file for miner secret identity", metavar='PATH')
    parser.add_argument('-p', '--peers', help="Load/save file for found peers", default='peers.txt', metavar='PATH')
    parser.add_argument('-l', '--listen', metavar="LISTEN", default='127.0.0.1:' + str(POOL_PORT), help="Listener port for miners")
    opts = parser.parse_args()
    LOG.basicConfig(level=opts.loglevel)
    return opts


def main():
    opts = parse_args()
    bootstrap_peers = read_peers(opts.peers)
    identity = Identity('.bismuth.key')
    LOG.warning('Pool identity: %s', identity.address)
    peers = PeerManager(identity)
    if opts.listen:
        LOG.warning('Pool listen: %s', opts.listen)
        miners = Miners(peers, opts.listen)
    try:
        # peers.add(('127.0.0.1', '5868'))
        while True:
            shuffle(bootstrap_peers)
            for sockaddr in bootstrap_peers[:10]:
                peers.add(IpPort(*sockaddr))
                time.sleep(0.1)
            Abuse.tick()
            print("")
            print("------------------------------")
            print("Mempool")
            for row in peers.consensus(peers.mempool, False):
                print(" %s %d %.3f" % row)
            consensus = peers.consensus(None, True)
            if len(consensus):
                print("\nConsensus")
                for row in consensus:
                    print(" %s %d %.3f" % row)
            if len(peers.peers):
                print("\nClients")
                for peer, client in peers.peers.items():
                    print(" %r %r" % (peer, client.status()))
            difficulty = peers.difficulty()
            print("\nDifficulty:", difficulty)
            if len(ResultsManager.HEIGHTS):
                print("\nCandidates:")
                sorted_heights = sorted(ResultsManager.HEIGHTS.items())
                for diff, result in sorted_heights:
                    print("\t%.2f = %r" % (diff, result))
                # Submit transaction with highest difficulty
                diff, result = sorted_heights[-1]
                for peer in peers.peers.values():
                    if peer.synched and int(diff) >= math.floor(peer._diff):
                        new_txn = ResultsManager.sign_blocks(identity, result, peer.mempool)
                        try:
                            peer.submit_block(new_txn)
                        except Exception:
                            LOG.exception('Peer %r - Error Submitting Block')
                print("")
            time.sleep(2)
    except KeyboardInterrupt:
        print("Caught Ctrl+C - stopping gracefully")
        miners.stop()
        peers.stop()

if __name__ == "__main__":
    sys.exit(main())
