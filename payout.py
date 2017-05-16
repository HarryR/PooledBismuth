from __future__ import print_function
import sqlite3
import os
import json
from collections import defaultdict
from common import Identity


def double_N(value, times):
    for N in range(0, times):
        value *= 2
    return value


def load_block(blockno, block_key):
    filename = 'audit/%d.block' % (blockno,)
    if not os.path.exists(filename):
        return False, None, None
    did_win = False
    difficulty = None
    try:
        with open(filename, 'rb') as handle:
            proofs = []
            for proof in handle:
                proof = json.loads(proof)
                if not did_win:
                    did_win = block_key == proof[3]
                    if did_win:
                        difficulty = proof[2]
                proofs.append(proof)
    except ValueError:
        return False, None, None
    return did_win, proofs, difficulty


def proof_histogram(proofs):
    # max_height = max([X[2] for X in proofs])
    min_height = min([X[2] for X in proofs])
    share_dist = defaultdict(int)
    work_counts = defaultdict(int)
    total_shares = 0
    named_shares = 0
    for proof in proofs:
        gap = abs(proof[2] - min_height)
        share = double_N(1.0, gap)
        total_shares += share
        if proof[1] is None:
            continue
        work_counts[proof[1]] += 1
        named_shares += share
        share_dist[proof[1]] += share
    return total_shares, named_shares, share_dist, work_counts, len(proofs)


myid = Identity('.bismuth.key')


pooldb = sqlite3.connect('.pool.db')
pooldb.text_factory = str
poolcur = pooldb.cursor()
poolcur.executescript("""
CREATE TABLE IF NOT EXISTS workproof (
    block_id INTEGER NOT NULL,
    address_id INTEGER NOT NULL,
    shares INTEGER NOT NULL,
    reward INTEGER NOT NULL,
    workcount INTEGER NOT NULL,
    PRIMARY KEY (block_id, address_id)
);

CREATE TABLE IF NOT EXISTS addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address VARCHAR(56) NOT NULL,
    total_reward DECIMAL DEFAULT 0,
    sent_reward DECIMAL DEFAULT 0,
    paid_upto INTEGER,
    total_work INTEGER,
    UNIQUE (address)
);

CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER NOT NULL PRIMARY KEY,
    stamp INTEGER NOT NULL,
    won INTEGER NOT NULL,
    total_shares INTEGER NOT NULL,
    nonce VARCHAR(32) NOT NULL,
    reward TEXT NOT NULL,
    address TEXT NOT NULL,
    difficulty INTEGER,
    total_work INTEGER,
    named_work INTEGER,
    named_shares INTEGER NOT NULL
);
""")


def make_address_ids(poolcur, addresses):
    placeholders = ','.join(['?'] * len(addresses))
    sql = "SELECT address, id FROM addresses WHERE address IN (%s)" % (placeholders,)
    poolcur.execute(sql, addresses)
    # found = {row[0]: row[1] for row in poolcur.fetchall()}
    found = dict(poolcur.fetchall())
    for address in addresses:
        if address not in found:
            poolcur.execute("INSERT INTO addresses (address) VALUES (?)", (address,))
            found[address] = poolcur.lastrowid
    return found


conn = sqlite3.connect("../Bismuth/static/ledger.db")  # open to select the last tx to create a new hash from
conn.text_factory = str
c = conn.cursor()
c.execute("""
    SELECT block_height, reward, openfield, timestamp, address FROM transactions
    WHERE address = recipient AND block_height > 90000 AND reward > 0
""")  # , (myid.public_key_hashed,))
result = c.fetchall()


for row in result:
    blockno = row[0] - 1
    did_win, proofs, difficulty = load_block(blockno, row[2])
    reward = float(row[1])
    total_shares = 0
    total_work = 0
    named_shares = 0
    if proofs:
        total_shares, named_shares, share_dist, work_counts, total_work = proof_histogram(proofs)
    named_work = 0
    print("Block %d = BIS %.2f" % (blockno, reward,))
    if did_win:
        address_ids = make_address_ids(poolcur, share_dist.keys())
        workproof_rows = list()
        address_stats_rows = list()
        for address, shares in share_dist.items():
            address_id = address_ids[address]
            print("DOOP", reward, named_shares, total_shares, shares)
            payout = (reward / named_shares) * shares
            print(' ', address, shares, payout)
            work_count = work_counts[address]
            named_work += work_count
            workproof_rows.append((blockno, address_id, shares, payout, work_count))
            address_stats_rows.append((work_count, address_id))

        poolcur.executemany("UPDATE addresses SET total_work = total_work + ? WHERE id = ?", address_stats_rows)
        poolcur.executemany("REPLACE INTO workproof VALUES (?, ?, ?, ?, ?)", workproof_rows)
        print("")

    poolcur.execute("""
    REPLACE INTO blocks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (blockno, row[3], int(did_win), total_shares, row[2], reward, row[4], difficulty, total_work, named_work, named_shares))

pooldb.commit()
