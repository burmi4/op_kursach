import hashlib

msg = "369471c5b09dd4d9627c0a0d7e72139c1f571035d1afc5d574300209a4f8e25f{\"n\":10}"
print(hashlib.sha256(msg.encode()).hexdigest())
