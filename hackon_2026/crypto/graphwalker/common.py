import hashlib

class Matrix2x2:
    def __init__(self, a, b, c, d, p):
        self.P = p
        self.vals = (a % self.P, b % self.P, c % self.P, d % self.P)

    def __mul__(self, other):
        if self.P != other.P:
            raise ValueError("Module P mismatch")
        
        a, b, c, d = self.vals
        x, y, z, w = other.vals

        return Matrix2x2(
            a * x + b * z, a * y + b * w,
            c * x + d * z, c * y + d * w,
            self.P
        )

    def __eq__(self, other):
        return self.vals == other.vals and self.P == other.P

    def __hash__(self):
        return hash(self.vals)

    def __repr__(self):
        return f"Mat{self.vals}"
    
    def trace(self):
        return (self.vals[0] + self.vals[3]) % self.P

    def det(self):
        return (self.vals[0] * self.vals[3] - self.vals[1] * self.vals[2]) % self.P
    
    def inv(self):
        det = self.det()
        if det == 0:
            raise ValueError("Determinant is 0")
        
        det_inv = pow(det, -1, self.P)
        
        a, b, c, d = self.vals
        return Matrix2x2(
            d * det_inv, -b * det_inv,
            -c * det_inv, a * det_inv,
            self.P
        )
    
    def __pow__(self, exponent):
        result = Matrix2x2(1, 0, 0, 1, self.P)
        base = self
        exp = exponent
        
        if exp < 0:
            base = base.inv()
            exp = -exp

        while exp > 0: 
            if exp % 2 == 1:
                result = result * base
            base = base * base
            exp //= 2
        return result

def stateful_matrix_gen(state, p):
    """
    Generates the next matrix statefully.
    Input: state (bytes)
    Output: next_state (bytes), Matrix2x2
    """
    counter = 0
    while True:
        # Mix state with counter to find a valid matrix in SL(2, p)
        h = hashlib.sha256(state + str(counter).encode()).digest()
        
        # Extract potential matrix values
        a = int.from_bytes(h[0:4], 'big') % p
        b = int.from_bytes(h[4:8], 'big') % p
        c = int.from_bytes(h[8:12], 'big') % p
        
        # Check invertibility of 'a'
        if pow(a, p-2, p) * a % p == 1:
             # d = (1 + bc) * a^-1 mod p
             d = ((1 + b*c) * pow(a, p-2, p)) % p
             
             # The new state is derived from the hash that succeeded
             new_state = hashlib.sha256(h).digest()
             return new_state, Matrix2x2(a, b, c, d, p)
        
        counter += 1
