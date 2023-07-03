import struct


bytes_to_word = lambda x: struct.unpack("<I", x)[0]
word_to_bytes = lambda x: struct.pack("<I", x)


class RelocatedByteArray(object):
    def __init__(self, backing, base):
        self.backing = bytearray(backing)
        self.base = base

    def __getitem__(self, index):
        if isinstance(index, slice):
            new_start = index.start - self.base if index.start else None
            new_stop = index.stop - self.base if index.stop else None
            s = slice(new_start, new_stop, index.step)
            return self.backing.__getitem__(s)
        else:
            return self.backing.__getitem__(index - self.base)

    def __setitem__(self, index, value):
        if isinstance(index, slice):
            new_start = index.start - self.base if index.start else None
            new_stop = index.stop - self.base if index.stop else None
            s = slice(new_start, new_stop, index.step)
            try:
                return self.backing.__setitem__(s, value)
            except:
                import ipdb; ipdb.set_trace()
        else:
            return self.backing.__setitem__(index - self.base, value)

    def patch(self, loc, new):
        if isinstance(new, str):
            new = new.encode("latin1")
        self[loc:loc + len(new)] = new

    def get_bytes_at(self, loc, n):
        return self[loc:loc + n]

    def get_word_at(self, loc):
        return bytes_to_word(self.get_bytes_at(loc, 4))

    def set_word_at(self, loc, value):
        self.patch(loc, word_to_bytes(value))
