"""
Stockham NTT algorithm
which is much faster than recursive NTT with divide-and-conquer
Source: https://github.com/pdroalves/fft_ntt_comparison/blob/master/stockham/stockham_ntt.py
"""

is_power2 = lambda n: (n & (n - 1)) == 0 

def get_primitive_root(n, p):
    k = (p-1) // n
    omega = pow(7,k,p)

    assert pow(omega, n, p) == 1

    return omega

def build_omega(n, p):
    omega = get_primitive_root(n, p)

    w = []
    for j in range(n):
        w.append(pow(omega,j,p))
    wInv = []
    for j in range(n):
        wInv.append(pow(w[j],p-2,p))

    return w, wInv

def CPU_NTT(data, w, p):
    N = len(data)
    assert N > 0 and is_power2(N)
    R = 2
    Ns = 1
    a = list(data)+[0]*(N-len(data))
    b = [0]*N
    while Ns < N:
        for j in range(N//R):
            NTTIteration(j,N,R,Ns,a,b,w,p)
        a,b = b,a
        Ns = Ns*R
    return a

def CPU_INTT(data, wInv, p):
    
    ninv = pow(len(data), -1, p)

    transformed_values = CPU_NTT(data, wInv, p)
    return [ninv*tv % p for tv in transformed_values]


def NTTIteration(j,N,R,Ns,data0,data1,w,p):
    v = [0]*R
    idxS = j
    w_index = ((j%Ns)*N)//(Ns*R)
    assert( ((j%Ns)*N)%(Ns*R) == 0)

    for r in range(R):
        v[r] = data0[idxS+r*(N//R)]*w[r*w_index] % p

    v = NTT(R,v,p)
    idxD = expand(j,Ns,R)
    for r in range(R):
        data1[idxD+r*Ns] = v[r]
    return

def INTTIteration(j,N,R,Ns,data0,data1,wInv,p):
    v = [0]*R
    idxS = j
    w_index = ((j%Ns)*N)//(Ns*R)
    assert( ((j%Ns)*N)%(Ns*R) == 0)

    for r in range(R):
        v[r] = data0[idxS+r*(N//R)]*wInv[r*w_index] % p

    v = NTT(R,v,p)
    idxD = expand(j,Ns,R)
    for r in range(R):
        data1[idxD+r*Ns] = v[r]
    return

def NTT(R,v,p):
    if R == 2:
        return [ (v[0] + v[1]) % p,
                 (v[0] - v[1]) % p]
    else:
        raise ValueError("NTT Error!")

def expand(idxL,N1,N2):
    return (idxL//N1)*N1*N2 + (idxL%N1)