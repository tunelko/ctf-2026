import random
import time

hint = []
for i in range(500):
    n = int.from_bytes(random.randbytes(8), byteorder='big')
    hint.append(n)

print("Bienvenido a la Lotería Cuántica")
print("Toma una pista")
time.sleep(1)
print(hint)

a = [random.getrandbits(32) for _ in range(11)]

print("La lista es esta:")
print(a)

random.shuffle(a)
time.sleep(1)
print("Mezclando...")
time.sleep(2)
print("Para ganar, adivina como ha quedado la lista finalmente!")

try:
    user_input = input("Introduce tu predicción (n1 n2 n3...): ")
    solve = list(map(int, user_input.split()))
    
    if len(solve) == 11:
        if solve == a:
            print("Has ganado el premio máximo!\nHackOn{F4ke_Fl4g!}")
        else:
            print("Respuesta incorrecta, vuelve a intentarlo.")
    else:
        print("longitud incorrecta de numeros")
except Exception as e:
    print("Error: Debes introducir solo números separados por espacios.")

