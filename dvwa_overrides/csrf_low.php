<?php

// CSRF (Low) override for Ghost Protocol: emit a per-request flag token on successful password change.
// This keeps the exercise non-guessable: the player must trigger the CSRF to see the token in the response.

if( isset( $_GET[ 'Change' ] ) ) {
    // Get input
    $pass_new  = $_GET[ 'password_new' ];
    $pass_conf = $_GET[ 'password_conf' ];

    // Do the passwords match?
    if( $pass_new == $pass_conf ) {
        // They do!
        $pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
        $pass_new = md5( $pass_new );

        // Update the database
        $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
        $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

        // Generate a per-request flag token to prove the CSRF fired
        if (!isset($_SESSION)) {
            session_start();
        }

        if (function_exists('random_bytes')) {
            $flag_token = bin2hex(random_bytes(4)); // 8 hex chars
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $flag_token = bin2hex(openssl_random_pseudo_bytes(4));
        } else {
            $flag_token = substr(md5(uniqid('', true)), 0, 8);
        }

        $_SESSION['csrf_flag'] = $flag_token;

        // Feedback for the user
        $html .= "<pre>Password Changed.</pre>";
        $html .= "<pre>FLAG: flag{csrf_{$flag_token}}</pre>";
    }
    else {
        // Issue with passwords matching
        $html .= "<pre>Passwords did not match.</pre>";
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
