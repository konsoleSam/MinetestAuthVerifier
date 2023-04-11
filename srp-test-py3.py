import sqlite3
import hashlib
import base64
#import srp
#Format (since 0.4.13) of password hash is #1#<salt>#<verifier>, with the
#parts inside <> encoded in the base64 encoding.
#<verifier> is an RFC 2945 compatible SRP verifier,
#of the given salt, password, and the player's name lowercased,
#using the 2048-bit group specified in RFC 5054 and the SHA-256 hash function.

connection=sqlite3.connect("auth.sqlite")
cursor=connection.cursor()
cursor.execute("SELECT * FROM [auth] WHERE name='owner'")
data=cursor.fetchone()

def long_to_bytes(n):
    l=[]#list()
    x=0
    off=0
    while x!=n:
        b = (n >> off) & 0xFF
        l.append(chr(b))
        x = x | (b << off)
        off+=8
    l.reverse()
    return ''.join(l).encode("latin-1")#six.b(''.join(l))

def H(*args, **kwargs ):
    width = kwargs.get('width', None)
    h = hashlib.sha256()
    for s in args:
        if s is not None:
            data = long_to_bytes(s) if isinstance(s, int) else s
            h.update(data)

    return int(h.hexdigest(),16)

def create_salted_verification_key(username,password,salt):
    N=int('AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73',16)
    g=int("2",16)
    verifier = long_to_bytes(pow(g,H(salt,H(username.encode()+':'.encode("latin-1")+password.encode())),N))
    return verifier

def minetest_auth_checker(username,password,key):
    salt,verifier=key.split("#")[2:]
    salt=base64.b64decode(salt+"==")
    verifier=base64.b64decode(verifier+"==")
    x=create_salted_verification_key(username.lower(),password,salt)
    return verifier==x

print(minetest_auth_checker("owner","",data[2]))

#cursor.execute("UPDATE [auth] SET [name]='owner19' WHERE [name]='owner';")
#connection.commit()

#salt,verifier=srp.create_salted_verification_key("owner".lower(), "", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
#key=f"#1#{base64.b64encode(salt).decode()[:-2]}#{base64.b64encode(verifier).decode()[:-2]}"
