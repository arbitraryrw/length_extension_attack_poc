import urllib
from modified_md5 import md5, padding

secret = "SuperSecretUniqueKey"
original_message = "accno=123&amnt=10.00&user=bob"
appended_message = "&accno=456&amnt=9999.00&user=nik"

# A third party implementation to sanity check
# import hashlib
# m = hashlib.md5()
# m.update(secret + original_message)
# print m.hexdigest()
# print m.digest_size
# print m.block_size

# Creating the original MAC(secret | msg)
original_digest = md5(secret + original_message).hexdigest()

print ("[+] Original message hex digest:\n\t-> " + original_digest)

# Execute the length extension attack by setting the state to the first block's hash value.
# This is supposed to represent a MAC we would legitimately calculate / send to the server, albeit insecure

# If we didn't know the size of m, we could guess the padded message length by doing:
# print (length_of_m_guess + len(padding(length_of_m_guess *8)))*8
# #for x in range(0,1000):
    # print (x + len(padding(x *8)))*8

extended_attack_hash = md5(state=original_digest.decode("hex"), count=512)
extended_attack_hash.update(appended_message)
extended_attack_digest = extended_attack_hash.hexdigest()

print ("[+] Length Extension attack message digest:\n\t-> " + extended_attack_digest)

# Now lets calculate a legitimate message to compare against the length extension attack above to make sure
# it is correct. This is done by calculating md5(secret | message | padding | appended_message)
extended_legit_hash = md5()
extended_legit_hash.update(secret + original_message + padding(len(secret + original_message) * 8) + appended_message)
extended_legit_digest = extended_legit_hash.hexdigest()

print ("[+] Legitimate extended message digest:\n\t-> " + extended_legit_digest)

def validate_attack():
    return extended_legit_digest == extended_attack_digest

if(validate_attack()):
    print("-"*40)
    print("[!] Successfully crafted MAC without the key!")
    print ("\t[-] Original message:\n\t\t-> " + original_message)
    print ("\t[-] Length extension attack message:\n\t\t-> " +
           original_message + urllib.quote(padding(len(secret + original_message) * 8)) + appended_message
           )

    print("\t[-]Attack digest: "+ extended_attack_digest)
    print("\t[-]Legitimate extended digest: "+ extended_legit_digest)


