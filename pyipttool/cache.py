import os
import pprint
import pickle
import sqlite3

class Writer:
    def __init__(self, records):
        self.records = records

    def save(self, filename):
        pickle.dump(self.records, open(filename, "wb" ) )

class Merger:
    def __init__(self, sqlite_filename = 'output.sqlite'):
        self.conn = None
        try:
            self.conn = sqlite3.connect(sqlite_filename)
        except sqlite3.Error as e:
            print(e)

        self.cursor = self.conn.cursor()
        self.create_table()
        self.create_index()

    def create_table(self):
        sql = """ CREATE TABLE IF NOT EXISTS Blocks (
                                        id integer PRIMARY KEY,
                                        address integer,
                                        end_address integer,
                                        sync_offset integer,
                                        offset integer,
                                        cr3 integer
                                    ); """

        try:
            self.cursor.execute(sql)
        except sqlite3.Error as e:
            print(e)

    def create_index(self):
        sqls = (
            "CREATE INDEX blocks_address ON Blocks(address)",
            "CREATE INDEX blocks_end_address ON Blocks(end_address)",
            "CREATE INDEX blocks_cr3_address ON Blocks(cr3)",
        )

        for sql in sqls:
            try:
                self.cursor.execute(sql)
            except sqlite3.Error as e:
                print(e)

    def add_record_directory(self, dirname):
        for basename in os.listdir(dirname):
            if not basename.endswith('.cache'):
                continue
            self.add_record_file(os.path.join(dirname, basename))

    def add_record_file(self, filename):
        try:
            records = pickle.load(open(filename, "rb"))
        except:
            print("Error loading " + filename)
            return

        sql = '''INSERT INTO Blocks(address, end_address, sync_offset, offset, cr3) VALUES(?,?,?,?,?) '''
        for record in records:
            args = (record['IP'], record['EndIP'], record['SyncOffset'], record['Offset'], record['CR3'])
            self.cursor.execute(sql, args)

    def add_record_files(self, filenames):
        for filename in filenames:
            self.add_record_file(filename)

    def save(self):
        self.conn.commit()

class Reader:
    def __init__(self, sqlite_filename):
        try:
            self.conn = sqlite3.connect(sqlite_filename)
        except sqlite3.Error as e:
            print(e)

    def enumerate_block_range(self, cr3 = 0, start_address = 0, end_address = 0):
        cursor = self.conn.cursor()
        cursor.execute("SELECT offset, address, end_address, sync_offset FROM Blocks WHERE cr3=? and address >= ? and address <= ?", (cr3, start_address, end_address))

        for (offset, address, end_address, sync_offset) in cursor.fetchall():
            yield (offset, address, end_address, sync_offset)

    def enumerate_blocks(self, address = None, cr3 = 0):
        cursor = self.conn.cursor()
        cursor.execute("SELECT sync_offset, offset FROM Blocks WHERE cr3=? and end_address >= ? and address <= ?", (cr3, address, address))

        for (sync_offset, offset) in cursor.fetchall():
            yield (sync_offset, offset)

if __name__ == '__main__':
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='pyipt')
    parser.add_argument('-c', action = "store", dest = "cache_file")
    parser.add_argument('-o', action = "store", dest = "output")

    args = parser.parse_args()
    
    merger = Merger(args.output)
    merger.add_record_directory(args.cache_file)
    merger.save()
