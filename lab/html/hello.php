<?php
// PHP2Shell lab target — deliberately trivial.
// The vulnerability is in the PHP runtime, not the application:
// a "hello world" is enough.
header('Content-Type: text/plain');
echo 'P2S-LAB ok ', PHP_VERSION, "\n";
