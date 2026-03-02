<?php

define('DB_PATH', '/var/www/data/helios.db');

$station_internal = array(
    'sync_user'     => 'nova',
    'sync_pass'     => '4RnWMuOsAR5T3KClI6VQlH1ATq7P0qpNSoMrYKS2UoShMv4yqrMgF8WW3cIQOkkSWpxxUNxrd0QAUOtckj59KLCNaVaVEGtg211XJElGCyybEihGKPqeJSyVbuik0j1Hh0gBIb2NGLBWYTPcbd9uxqQLJnBXwy862xbASvOMtp2nS9pW9zwXckH9YFFi0A0rMAkjFxs4L2En3oSfR1PmsWQv0uYDnBCcnulPFEvRYAoGccdiMlWQx05PDvCu2eXq7fOcj7g8sigSWzR2xuKo24XqvDpQ3OmwhQI0D3BvTdW3LgEAr2yR5vaZFVzu0XFsk1P2yEdwMJTOi0fqobr8qNzpHGLIfKZq3ULNOqcYeXqoaCRQifycsP3coLf20cSPZ71zv1kcDIY5KBI8qB2MKorRq0uOLRzf5KMNJPPxMpLO89a8vbFAqnoU7m9vNiPkYyrSfoHegWJAjNpY2Ft3v2KvgPrZOZrWhLQpGKV9loXxF7C2jwaYscNHQQfmRF1iSs4V6ulE8IHjtjHMghsvZSegOaRRdF0JnrNCToxWdG4RMxfGt3eXz8cHT070MVhyJTZDl0iKN1RfKJ8RlEVZT4IQwPWPOb8FxkEV1fuHi89Ppq8G50qDWpRfHtt0vvJrflGfdpLqkz7RBvVneCIiwmTnIlYf3TEuZrrSNfhmmCZRlYtnOcndlNl9nTiWtgoaeZzG2svfArVXHvl3KHAxIybrv9cePOYMNSOoWDtu0KkSLNQJlegH2CWbbliU7IKEhjnN3Ze5VfiotUmXoVxrC94EdtopnLOrPDe5ciLwbmNO1qrAerQZcxNjQ7vIWL6LQHpsQd4mkqmscyhbdr3PgbQ2fkTIXSlMoyQFINUVTOMk8uQ4RAT91njz9cXIxt5gWvVDrmSboolfyRIIlWjreU3Yqox8s58uczPWZgH3SrzUw1a6rz7QfDG0neqsi7VYJ85B4FVGNtyQ6BuiLCjthzLEhn52f9nk1DSpBnb2LSuAX8X0',
    'sync_protocol' => 'ssh',
    'sync_port'     => 22,
    'sync_script'   => '/home/nova/orbit-sync.sh'
);

function get_db() {
    $db = new SQLite3(DB_PATH);
    $db->busyTimeout(5000);
    return $db;
}
?>
