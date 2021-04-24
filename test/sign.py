import sys
sys.path.append('../build')

import pydilithium;

message = "example message for verification";

# Step 1: Create keys
pydilithium.pqcrystals_dilithium2_ref_keypair()

print("Sign public key:")
print(pydilithium.pqcrystals_get_pk())
print("")
print("Sign secret key:")
print(pydilithium.pqcrystals_get_sk())
print("")
print("Original message:")
print(message)
print("")
f = open('key.public', 'w')
f.write(pydilithium.pqcrystals_get_pk())
f.close()
f = open('key.secret', 'w')
f.write(pydilithium.pqcrystals_get_sk())
f.close()

# Step 2: Sign message
signed_message = pydilithium.pqcrystals_dilithium2_ref(message, len(message))
print("Signed message:")
print(signed_message)
print("")

# Step 3: Check message
f = open('key.public', 'r')
pk = f.readline()
f.close()

pydilithium.pqcrystals_set_pk(pk)
check = pydilithium.pqcrystals_dilithium2_ref_open(signed_message, len(signed_message))
print("Restored message:")
print(check)
print("")

if check == None :
	print("Failed.");
else :
	print("Success!")

