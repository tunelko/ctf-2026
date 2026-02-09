<?php

class Message
{
    public function __construct($to, $from, $image)
    {
        $this->to = $to;
        $this->from = $from;
        $this->image = $image;
        $this->filePath = tempnam("/tmp/messages/", "") . ".txt"; // TODO: send messages
    }

    public function __destruct()
    {
        file_put_contents($this->filePath, sprintf(
            "Hey %s! Take a look at this meme: %s! - %s",
            $this->to,
            $this->from,
            $this->image,
        ));
    }
}

if (isset($_POST["message"])) {
    $msgXml = new DOMDocument();
    $msgXml->loadXML($_POST["message"], LIBXML_DTDLOAD);
    if ($msgXml->schemaValidate("valid_message.xsd")) {
        $msgObj = new Message(
            $msgXml->getElementsByTagName("to")[0]->nodeValue,
            $msgXml->getElementsByTagName("from")[0]->nodeValue,
            $msgXml->getElementsByTagName("image")[0]->nodeValue
        );
        echo sprintf(
            "Message stored %s!",
            $msgObj->filePath
        );
    } else {
        echo "Invalid XML!";
    }
} else if (isset($_FILES["image"])) {
    $imageTmp = $_FILES["image"]["tmp_name"];
    $imageSize = $_FILES["image"]["size"];
    $imageExt = strtolower(pathinfo($_FILES["image"]["name"], PATHINFO_EXTENSION));
    $imageMime = mime_content_type($imageTmp);
    $allowedExt = array("jpg", "jpeg", "gif", "png");
    $allowedMime = array("image/jpeg", "image/gif", "image/png");
    if (in_array($imageExt, $allowedExt) === false)
        die("Invalid extension!");
    if (in_array($imageMime, $allowedMime) === false)
        die("Invalid mime type!");
    if (getimagesize($imageTmp) === false || $imageSize > 185)
        die("Invalid size!");
    $uploadPath = tempnam("/tmp/images/", "") . "." . $imageExt;
    move_uploaded_file($imageTmp, $uploadPath);
    echo sprintf(
        "Image uploaded %s!",
        $uploadPath
    );
} else {
    echo highlight_file(__FILE__, true);
}
