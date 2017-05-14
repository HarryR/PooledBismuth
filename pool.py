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
import socket
import re
import hashlib
import argparse
import base64
from collections import defaultdict, namedtuple
import logging
import logging as LOG

from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random

import fastminer


PROTO_VERSION = "mainnnet0009"
MINER_VERSION_ROOT = "morty"

POOL_PORT = 5659
STRIKE_TIMEOUT = 300
STRIKE_COUNT = 3
CONNECT_TIMEOUT = 5
MINER_TUNE_GOAL = 10
MINER_TUNE_HISTORY = 10


class Abuse(object):
    ip_seen = defaultdict(int)
    ip_strikes = defaultdict(int)

    @classmethod
    def tick(cls):
        now = time.time()
        remove_list = list()
        for ip, seen in cls.ip_seen.items():
            if seen < (now - STRIKE_TIMEOUT):
                remove_list.append(ip)
        for ip in remove_list:
            cls.reset(ip)

    @classmethod
    def strikes(cls, ip):
        return cls.ip_strikes.get(ip, 0)

    @classmethod
    def strike(cls, ip):
        if ip == '127.0.0.1':
            return False
        cls.ip_strikes[ip] += 1
        cls.ip_seen[ip] = time.time()
        strikes = cls.ip_strikes[ip]
        if strikes >= STRIKE_COUNT:
            LOG.warning('IP %r - Blocked (%d strikes)', ip, strikes)
            return True
        return False

    @classmethod
    def reset(cls, ip):
        if ip in cls.ip_seen:
            del cls.ip_seen[ip]
        if ip in cls.ip_strikes:
            del cls.ip_strikes[ip]

    @classmethod
    def blocked(cls, ip):
        strikes = cls.ip_strikes.get(ip, 0)
        seen = cls.ip_seen.get(ip, None)
        if seen is not None:
            now = time.time()
            if seen < (now - STRIKE_TIMEOUT):
                cls.reset(ip)
                strikes = 0
        return strikes >= STRIKE_COUNT


class Identity(object):
    def __init__(self, keyfile=None, keydata=None):
        if keyfile and keydata is None:
            if not os.path.exists(keyfile):
                random_generator = Random.new().read
                secret = RSA.generate(1024, random_generator)
                with open(keyfile, 'wb') as handle:
                    handle.write(str(secret.exportKey()))
            else:
                with open(keyfile, 'rb') as handle:
                    keydata = handle.read()
        if keydata:
            secret = RSA.importKey(keydata)

        self.secret = secret
        self.public = secret.publickey()
        public_key_readable = str(self.public.exportKey())
        self.public_key_hashed = base64.b64encode(public_key_readable)
        self.address = hashlib.sha224(self.public_key_hashed).hexdigest()
        self.signer = PKCS1_v1_5.new(self.secret)

    def sign(self, data):
        return base64.b64encode(self.signer.sign(data))

class ProtocolBase(object):
    def __init__(self, sock, manager):
        self.peer = sock.getpeername()
        self.sock = sock
        self.manager = manager

    def _send(self, *args):
        for data in args:
            data = str(data)
            self.sock.sendall((str(len(data))).zfill(10))
            self.sock.sendall(data)

    def _recv(self, datalen=10):
        data = self.sock.recv(datalen)
        if not data:
            return None
        data = int(data)

        chunks = []
        bytes_recd = 0
        while bytes_recd < data:
            chunk = self.sock.recv(min(data - bytes_recd, 2048))
            if chunk == b'':
                raise RuntimeError("Socket connection broken")
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)
        segments = b''.join(chunks)
        return segments


MinerJob = namedtuple('MinerJob', ('diff', 'address', 'block'))
MinerResult = namedtuple('MinerResult', ('diff', 'address', 'block', 'nonce'))


class Miners(object):
    def __init__(self, peers, bind=None, max_peers=1000):
        if bind is None:
            bind = ('127.0.0.1', POOL_PORT)
        elif isinstance(bin, str):
            bind = bind.split(':')
            bind[1] = int(bind[1])
        self.peers = peers
        self.pool = Pool(max_peers)
        self.server = StreamServer(bind, self._on_connect, spawn=self.pool)
        self.server.start()

    def on_found(self, result, miner):
        if not fastminer.verify(result.address, result.nonce, result.block, int(result.diff)):
            ip = miner.peer[0]
            Abuse.strike(ip)
            if Abuse.blocked(ip):
                miner.close()
            LOG.error('Invalid block submitted!')
            return False
        # TODO: save contribution log for miner
        ResultsManager.on_result(result)
        return True

    def stop(self):
        self.server.stop()
        self.pool.kill()

    def _on_connect(self, socket, address):
        if Abuse.blocked(address[0]):
            LOG.debug('Miner %r - accept() blocked: abuse', address)
            socket.close()
            return
        client = MinerClient(socket, self)
        client.run()


class MinerClient(ProtocolBase):
    def __init__(self, sock, manager):
        super(MinerClient, self).__init__(sock, manager)
        self._version_ok = False
        self._history = []
        self._diff = 37
        self._last_found = None

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

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
            ideal_diff -= 0.51
        else:
            if self._last_found > (time.time() - MINER_TUNE_GOAL):
                ideal_diff += 0.49
        peers_diff = self.manager.peers.difficulty()
        if ideal_diff > peers_diff:
            ideal_diff = peers_diff
        self._diff = ideal_diff
        # Trim history
        if len(self._history) > MINER_TUNE_HISTORY:
            self._history = self._history[0 - MINER_TUNE_HISTORY:]

    def _cmd_sendsync(self):
        # They've mistaken us for a regular node, no a pool
        pass

    def _cmd_version(self):
        version = self._recv().split('.')
        self._version_ok = version[0] == MINER_VERSION_ROOT
        if self._version_ok:
            LOG.info('Miner %r - Accepted, version: %r', self.peer, version)
        self._send('ok' if self._version_ok else 'notok')

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
            LOG.exception("Miner %r - Rejecting Items: %r - %r", self.peer, items, ex)
            Abuse.strike(self.peer[0])
            return self._cmd_miner_fetch()  # wat u send, thafuq?
        if result:
            if self.manager.on_found(result, self):
                if self._last_found is not None:
                    mine_duration = time.time() - self._last_found
                    self._history.append((self._diff, mine_duration))
                self._last_found = time.time()
            else:
                # If its submitting shitty jobs, what do we do?
                pass
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
                    raise RuntimeError('Miner %r - Unknown CMD: %r' % (self.peer, cmd_name))
                LOG.info("Miner %r - Invalid Command: %r", self.peer, cmd_name)
                cmd_func()
        except Exception as ex:
            LOG.exception("Miner %r - Error running: %r", self.peer, ex)
            Abuse.strike(self.peer[0])
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
                (1, "3dc735c74859de7e173b255851b13d32fed942c69b8f76b1cbdbd34a", None)
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
                raise RuntimeError("Peer %r - protocol mismatch: %r %r" % (self.peer, data, PROTO_VERSION))
                return False
        except Exception as ex:
            Abuse.strike(self.peer[0])
            LOG.warning("Peer %r - Connect/Hello error: %r", self.peer, ex)
            return False
        LOG.info('Peer %r - Connected', self.peer)
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
                LOG.warning('Peer %r - Unknown CMD: %r' % (self.peer, cmd_name))
                self.close()
                return False

            LOG.info("Peer %r - Sent: %r", self.peer, cmd_name)
            cmd_func()
        return True


class ResultsManager(object):
    HEIGHTS = dict()
    BLOCK = None
    HIGHEST = 0

    @classmethod
    def on_consensus(cls, block):
        if cls.BLOCK == block:
            return
        cls.HEIGHTS = dict()
        cls.BLOCK = block
        cls.HIGHEST = 0
        LOG.warning('New consensus: %r', block)

    @classmethod
    def on_result(cls, result):
        if cls.BLOCK and result.block != cls.BLOCK[1]:
            return False
        if result.diff <= cls.HIGHEST:
            return False
        cls.HIGHEST = result.diff
        cls.HEIGHTS[int(result.diff)] = result
        LOG.warning('New highest for %s: %.2f', result.block, result.diff)
        return True

    @classmethod
    def sign_blocks(cls, identity, result, mempool):
        block_send = list()
        for dbdata in mempool:
            transaction = (
                str(dbdata[0]), str(dbdata[1][:56]), str(dbdata[2][:56]), '%.8f' % float(dbdata[3]), str(dbdata[4]), str(dbdata[5]), str(dbdata[6]),
                str(dbdata[7]))  # create tuple
            # print transaction
            block_send.append(transaction)  # append tuple to list for each run
            removal_signature.append(str(dbdata[4]))  # for removal after successful mining

        block_timestamp = '%.2f' % time.time()
        transaction_reward = (str(block_timestamp), str(result.address[:56]), str(result.address[:56]), '%.8f' % float(0), "0", str(result.nonce))  # only this part is signed!

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
        if peer not in self.peers and not Abuse.blocked(peer[0]):
            print("Adding peer", peer)
            return spawn(self._run, peer)

    def difficulty(self):
        values = [peer._diff for peer in self.peers.values()]
        if len(values):
            return sum(values) / float(len(self.peers))
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
            blocks = [peer.blocks[-1] for peer in self.peers.values() if peer.synched]
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
                Abuse.strike(peer[0])
                LOG.info("Peer %s:%d - Connect Error (%d strikes): %r",
                         peer[0], int(peer[1]), Abuse.strikes(peer[0]), ex)
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
                    Abuse.strike(peer[0])
                    LOG.info("Peer handshake with %s:%d (%d strikes) - %r",
                             peer[0], int(peer[1]), Abuse.strikes(peer[0]), ex)
                else:
                    Abuse.reset(peer[0])
                    client.run()
                if fail:
                    client.close()
                    client = None
        except Exception as ex:
            LOG.exception("Peer run error (%r) %r", peer, ex)
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


def read_peers(peers_file="../peers.txt"):
    return [('127.0.0.1', 5658)]
    """
    return [
        ('127.0.0.1', 5658),
        ('127.0.0.1', POOL_PORT),
    ]
    """
    with open(peers_file, 'r') as handle:
        peers = [ast.literal_eval(row) for row in handle]
        shuffle(peers)
        return peers


def parse_args():
    parser = argparse.ArgumentParser(description='FastBismuth Node')
    parser.add_argument('-v', '--verbose', action='store_const',
                        dest="loglevel", const=logging.INFO,
                        help="Log informational messages")
    parser.add_argument('--debug', action='store_const', dest="loglevel",
                        const=logging.DEBUG, default=logging.WARNING,
                        help="Log debugging messages")
    parser.add_argument('--keyfile', help="Load/save file for miner secret identity", metavar='PATH')
    parser.add_argument('-p', '--peers', help="Load/save file for found peers", metavar='PATH')
    parser.add_argument('-l', '--listen', metavar="LISTEN", default='127.0.0.1:' + str(POOL_PORT), help="Listener port for miners")
    opts = parser.parse_args()
    logging.basicConfig(level=opts.loglevel)
    return opts


def main():
    opts = parse_args()
    peer_list = read_peers()
    identity = Identity('.bismuth.key')
    LOG.warning('Pool identity: %s', identity.address)
    peers = PeerManager(identity)
    if opts.listen:
        LOG.warning('Pool listen: %s', opts.listen)
        miners = Miners(peers, opts.listen)
    try:
        # peers.add(('127.0.0.1', '5868'))
        while True:
            shuffle(peer_list)
            for peer in peer_list[:10]:
                peers.add(peer)
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
                        peer.submit_block(new_txn)
                print("")
            time.sleep(2)
    except KeyboardInterrupt:
        print("Caught Ctrl+C - stopping gracefully")
        miners.stop()
        peers.stop()

if __name__ == "__main__":
    sys.exit(main())
