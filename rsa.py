import random
from sympy import primerange
from sympy import mod_inverse
import json
import base64
import os

# =====================
# Funções de chaves
# =====================
def salvar_chaves(public_key, private_key, filename="keys.pain"):
    dados = {
        "public_key": {
            "e": base64.b64encode(str(public_key[0]).encode()).decode(),
            "n": base64.b64encode(str(public_key[1]).encode()).decode()
        },
        "private_key": {
            "d": base64.b64encode(str(private_key[0]).encode()).decode(),
            "n": base64.b64encode(str(private_key[1]).encode()).decode()
        }
    }
    with open(filename, "w") as f:
        json.dump(dados, f, indent=4)
    print(f"✅ Chaves salvas em {filename}")

def carregar_chaves(filename="keys.pain"):
    with open(filename, "r") as f:
        dados = json.load(f)

    public_key = (
        int(base64.b64decode(dados["public_key"]["e"]).decode()),
        int(base64.b64decode(dados["public_key"]["n"]).decode())
    )
    private_key = (
        int(base64.b64decode(dados["private_key"]["d"]).decode()),
        int(base64.b64decode(dados["private_key"]["n"]).decode())
    )
    return public_key, private_key

# =====================
# Funções RSA
# =====================
def find_inverse_multiplicative(crypto_key, qtd_coprimes):
    return mod_inverse(crypto_key, qtd_coprimes)

def mdc(x, y):
    while y:
        x, y = y, x % y
    return x

def count_coprimes(p,q):
    return ((p-1)*(q-1))

def random_primes():
    primes = list(primerange(1000, 10000))
    return random.sample(primes, 2)

def rsa():
    primes = random_primes()
    product_primes = primes[0]*primes[1]
    qtd_coprimes = count_coprimes(primes[0],primes[1])
    cripto_key = 65537
    public_key=(cripto_key,product_primes)
    descript_key = find_inverse_multiplicative(cripto_key,qtd_coprimes)
    private_key=(descript_key,product_primes)
    return (public_key, private_key)

# =====================
# Criptografia com bytes e Base64
# =====================
def encrypt_message(message: str, public_key) -> bytes:
    """Recebe uma string e retorna os bytes da mensagem criptografada"""
    key, n = public_key
    encrypted_numbers = [pow(b, key, n) for b in message.encode("utf-8")]
    # cada número vira 4 bytes (big endian)
    encrypted_bytes = b''.join(num.to_bytes(4, "big") for num in encrypted_numbers)
    return encrypted_bytes

def decrypt_message(encrypted_bytes: bytes, private_key) -> str:
    """Recebe bytes criptografados e retorna a string descriptografada"""
    key, n = private_key
    # pega blocos de 4 bytes -> int
    encrypted_numbers = [int.from_bytes(encrypted_bytes[i:i+4], "big") 
                         for i in range(0, len(encrypted_bytes), 4)]
    decrypted_bytes = bytes([pow(num, key, n) for num in encrypted_numbers])
    return decrypted_bytes.decode("utf-8", errors="ignore")

def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode()

def from_base64(data_str: str) -> bytes:
    return base64.b64decode(data_str.encode())

# =====================
# Menu Interativo
# =====================
def menu():
    while True:
        print("\n🔐 === MENU RSA ===")
        print("1️⃣  Gerar novas chaves")
        print("2️⃣  Encriptar uma mensagem")
        print("3️⃣  Decriptar uma mensagem")
        print("0️⃣  Sair")
        opcao = input("Escolha: ").strip()

        if opcao == "1":
            pub, priv = rsa()
            filename = input("Nome do arquivo .pain para salvar (padrão: keys.pain): ").strip() or "keys.pain"
            salvar_chaves(pub, priv, filename)

        elif opcao == "2":
            filename = input("Arquivo .pain com a chave pública: ").strip()
            if not os.path.exists(filename):
                print("❌ Arquivo não encontrado!")
                continue
            pub, _ = carregar_chaves(filename)
            mensagem = input("Digite a mensagem a ser encriptada: ")
            encrypted_bytes = encrypt_message(mensagem, pub)
            encrypted_b64 = to_base64(encrypted_bytes)
            print("📦 Mensagem encriptada (Base64, copia e guarda):")
            print(encrypted_b64)

        elif opcao == "3":
            filename = input("Arquivo .pain com a chave privada: ").strip()
            if not os.path.exists(filename):
                print("❌ Arquivo não encontrado!")
                continue
            _, priv = carregar_chaves(filename)
            mensagem_b64 = input("Digite a mensagem encriptada (Base64): ").strip()
            try:
                encrypted_bytes = from_base64(mensagem_b64)
                decrypted = decrypt_message(encrypted_bytes, priv)
                print(f"💬 Mensagem decriptada: {decrypted}")
            except Exception as e:
                print(f"❌ Erro ao decriptar: {e}")

        elif opcao == "0":
            print("👋 Saindo...")
            break
        else:
            print("❌ Opção inválida!")

if __name__ == "__main__":
    menu()
