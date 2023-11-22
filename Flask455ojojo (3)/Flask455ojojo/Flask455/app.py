from Crypto.Hash import SHA256
import random
from flask import Flask, render_template, request
from ast import literal_eval
from flask_session import Session

app = Flask(__name__, template_folder='Templates')
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
DEFAULT_BLOCK_SIZE = 128
BYTE_SIZE = 128
hash_algorithm = "SHA-256"  # will be used by default


def miller_rabin(n, k=10):
    if n == 2:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def primality_test(n):
    if n < 2:
        return False
    low_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
                  67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
                  149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
                  229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
                  313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401,
                  409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491,
                  499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
                  601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683,
                  691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
                  809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887,
                  907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    if n in low_primes:
        return True
    for prime in low_primes:
        if n % prime == 0:
            return False
    return miller_rabin(n)

def generate_large_prime(keysize):
    while True:
        num = random.randrange(2 ** (keysize - 1), 2 ** keysize)
        if primality_test(num):
            return num

def key_generated(keysize):
    print("Generating prime p...")
    p = generate_large_prime(keysize)
    print("Generating prime q...")
    q = generate_large_prime(keysize)
    n = p * q
    m = (p - 1) * (q - 1)

    print("Generating e that is relatively prime to (p-1)*(q-1)...")
    while True:
        e = random.randrange(2 ** (keysize - 1), 2 ** keysize)
        if compute_gcd(e, m) == 1:
            break

    print("Calculating d that is mod inverse of e...")
    d = find_mod_inverse(e, m)

    public_key = (n, e)

    return public_key, (n, d)

def compute_gcd(x, y):
    while y:
        x, y = y, x % y
    return abs(x)

def find_mod_inverse(a, m):
    if compute_gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m

    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

def get_blocks_from_text(message, block_size=DEFAULT_BLOCK_SIZE):
    message_bytes = message.encode('ascii')
    block_ints = []

    for block_start in range(0, len(message_bytes), block_size):
        block_int = 0
        for i in range(block_start, min(block_start + block_size, len(message_bytes))):
            block_int += message_bytes[i] * (BYTE_SIZE ** (i % block_size))
        block_ints.append(block_int)

    return block_ints
def get_text_from_blocks(block_ints, message_length, block_size=DEFAULT_BLOCK_SIZE):
    message = []

    for block_int in block_ints:
        block_message = []
        for i in range(block_size - 1, -1, -1):
            if len(message) + i < message_length:
                ascii_number = block_int >> (i * 7) & 0x7F

                # Check if the calculated ASCII number is valid 
                if 0x20 <= ascii_number <= 0x7E:  
                    block_message.insert(0, chr(ascii_number))
                else:
                    # Replace invalid bytes with ?
                    block_message.insert(0, '?')

        message.extend(block_message)

    return ''.join(message)


def custom_pow(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent // 2
        base = (base * base) % modulus
    return result

def encrypt_message(message, public_key, block_size=DEFAULT_BLOCK_SIZE):
    encrypted_blocks = []

    # Extract public key components (n, e)
    n, e = public_key

    # Ensure that the message is a multiple of the block size
    padded_message = message.ljust((len(message) // block_size + 1) * block_size, '\0')

    for block in get_blocks_from_text(padded_message, block_size):
        encrypted_block = custom_pow(block, e, n)
        encrypted_blocks.append(encrypted_block)

    return encrypted_blocks

def decrypt_message(private_key, encrypted_blocks, message_length):
    decrypted_blocks = []

    n, d = private_key

    for encrypted_block in encrypted_blocks:
        decrypted_block = custom_pow(encrypted_block, d, n)
        decrypted_blocks.append(decrypted_block)

    print(f"Decrypted Blocks: {decrypted_blocks}")

    return get_text_from_blocks(decrypted_blocks, message_length, DEFAULT_BLOCK_SIZE)





def generate_random_message(length):
    import random
    import string
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def generate_signature(message, private_key):
    # Extract private key components (n, d)
    n, d = private_key

    # Hash the message using SHA-256
    hashed_message = int(SHA256.new(message.encode()).hexdigest(), 16)

    # Sign the hashed message using the private key
    signature = custom_pow(hashed_message, d, n)

    return signature

def verify_signature(message, public_key, signature):
    # Extract public key components (n, e)
    n, e = public_key

    # Hash the message using SHA-256
    hashed_message = int(SHA256.new(message.encode()).hexdigest(), 16)

    # Verify the signature using the public key
    decrypted_signature = custom_pow(signature, e, n)
    return decrypted_signature == hashed_message

def generate_key(keysize):
    print(f"Generating key of size {keysize} bits...")
    public_key, private_key = key_generated(keysize)
    return public_key, private_key

# def main():
#     # Generate a key pair
#     keysize = 2048
#     public_key, private_key = key_generated(keysize)

#     # Original message
#     original_message = "Hello, this is a test message!"

#     # Encrypt the message
#     encrypted_blocks = encrypt_message(original_message, public_key)

#     # Decrypt the message
#     decrypted_message = decrypt_message(private_key, encrypted_blocks, len(original_message))

#     # Print results
#     print(f"Original Message: {original_message}")
#     print(f"Encrypted Blocks: {encrypted_blocks}")
#     print(f"Decrypted Message: {decrypted_message}")
# if __name__=='__main__':
#     main()

@app.route('/')
def home():
    return render_template('home.html')


from flask import Flask, render_template, request, session
@app.route('/generate', methods=['POST'])
def generate():
    keysize = request.form.get('keysize')

    if keysize not in ['1024', '2048']:
        return render_template('error.html', message='Invalid key size')

    try:
        keysize = int(keysize)
        public_key, private_key = generate_key(keysize)
        private_key_n = str(private_key[0])  # Convert to string
        private_key_d = str(private_key[1])  # Convert to string
        session['private_key_d'] = private_key_d
        session['private_key_n'] = private_key_n
        return render_template('generate.html', keysize=keysize, public_key=public_key, private_key_d=private_key_d, private_key_n=private_key_n)
    except Exception as e:
        print(f"Error generating key: {e}")
        return render_template('error.html', message='Error generating key')

# ... (Rest of the code)


@app.route('/encrypt', methods=['POST'])
def encrypt():
    keysize = int(request.form.get('keysize'))
    print(f"Received keysize: {keysize}")

    # Convert public key components to integers
    public_key_n = int(request.form.get('public_key_n'))
    public_key_e = int(request.form.get('public_key_e'))
    public_key = (public_key_n, public_key_e)
    print(f"Received public key: {public_key}")

    message = request.form.get('message')
    print(f"Received message: {message}")

    try:
        encrypted_blocks = encrypt_message(message, public_key)
        encrypted_message = ' '.join(map(str, encrypted_blocks))
        print(f"Encrypted message: {encrypted_message}")

        return render_template('result.html', keysize=keysize, operation='Encrypt', message=message, result=encrypted_message, original_length=len(message))
    except Exception as e:
        print(f"Error during encryption: {e}")
        return render_template('error.html', message='Error during encryption')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    keysize = int(request.form.get('keysize'))

    private_key_n = int(session.get('private_key_n', 0))
    private_key_d = int(session.get('private_key_d', 0))
    private_key = (private_key_n, private_key_d)

    encrypted_message = request.form.get('encrypted_message')
    encrypted_blocks = list(map(int, encrypted_message.split()))
    original_message_length = int(request.form.get('original_length'))

    original_message = str(request.form.get('message'))

    try:
        print(f"Key Size: {keysize}")
        print(f"Private Key Components: {private_key}")
        print(f"Encrypted Blocks: {encrypted_blocks}")

        if not encrypted_blocks:
            raise ValueError("Encrypted blocks is empty")

        decrypted_message = decrypt_message(private_key, encrypted_blocks, original_message_length)

        print(f"Decrypted Message: {decrypted_message}")

        if decrypted_message is None:
            raise ValueError("Error during decryption")

        return render_template('results.html', keysize=keysize, operation='Decrypt', message=encrypted_message,
                               result=decrypted_message, private_key=private_key)

    except Exception as e:
        print(f"Error during decryption: {e}")
        return render_template('error.html', message='Error during decryption')



if __name__ == '__main__':
    app.run(debug=True)
