<?php

$solr_url = "http://solr:8983/solr/ctf/select";

$query = isset($_GET['q']) ? $_GET['q'] : "";
$results = [];

function is_blocked($q) {
    return preg_match('/\b(AND|OR)\b|\*|<|>|\|\||&&|\||&|\+|\-/i', $q);
}

if ($query !== "" && !is_blocked($query)) {

    $solr_query = "name:" . $query;

    $url = $solr_url . "?q=" . urlencode($solr_query) . "&wt=json";

    $response = @file_get_contents($url);

    if ($response !== false) {
        $json = json_decode($response, true);
        $results = $json['response']['docs'] ?? [];
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Solar Shop</title>
<style>
body {
    font-family: Arial, sans-serif;
    background: #f4f6f8;
    margin: 0;
}
header {
    background: #1f2937;
    color: white;
    padding: 20px;
    text-align: center;
}
.container {
    max-width: 900px;
    margin: 30px auto;
    padding: 20px;
}
.search-box {
    display: flex;
    gap: 10px;
    margin-bottom: 30px;
}
.search-box input {
    flex: 1;
    padding: 12px;
    font-size: 16px;
}
.search-box button {
    padding: 12px 20px;
    background: #2563eb;
    color: white;
    border: none;
    cursor: pointer;
}
.products {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 20px;
}
.product {
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 4px 10px rgba(0,0,0,0.05);
}
.price {
    color: #16a34a;
    font-weight: bold;
}
.no-results {
    text-align: center;
    color: #6b7280;
    margin-top: 50px;
}
</style>
</head>
<body>

<header>
    <h1>🛍️ Solar Shop</h1>
    <p>Busca productos por nombre</p>
</header>

<div class="container">
    <form method="GET" class="search-box">
        <input type="text" name="q" placeholder="Buscar..." value="<?= htmlspecialchars($query) ?>">
        <button type="submit">Buscar</button>
    </form>

    <p>Ejemplo de búsqueda: <code>camiseta</code></p>

<?php if ($query !== ""): ?>
    <?php if (count($results) > 0): ?>
        <div class="products">
        <?php foreach ($results as $p): ?>
            <div class="product">
                <h3><?= htmlspecialchars($p['name'][0] ?? '') ?></h3>
                <p><?= htmlspecialchars($p['description'][0] ?? '') ?></p>
                <p class="price"><?= number_format($p['price'][0] ?? 0, 2) ?> €</p>
            </div>
        <?php endforeach; ?>
        </div>
    <?php else: ?>
        <div class="no-results">No se encontraron productos</div>
    <?php endif; ?>
<?php endif; ?>

</div>
</body>
</html>
