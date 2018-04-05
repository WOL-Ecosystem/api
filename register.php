<?php
//Display the errors
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// define variables and set to empty values
$email = $password = $repeat_password = $endState = "";
//Password must include at least one uppercase and one lowercase characters, one number and one special charachter
$password_pattern = "/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{8,32}$/";

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    if (isset($_POST["email"])) {
        if (filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
            $email = checkInput($_POST["email"]);
        }
        else {
            echo "Invalid email." . "</br>";
        }
    }

    if (isset($_POST["password"])) {
        if (preg_match($password_pattern, $_POST["password"])) {
            $password = checkInput($_POST["password"]);
        }
        else {
            echo "Invalid password." . "</br>";
        }
    }

    if (isset($_POST["repeat_password"])) {
        if (preg_match($password_pattern, $_POST["repeat_password"])) {
            $repeat_password = checkInput($_POST["repeat_password"]);
        }
        else {
            echo "Invalid repeat_password." . "</br>";
        }
    }

    if ($password != "" && $repeat_password != "") {
        if ($password === $repeat_password) {
            $credentials = array("email" => $email,"password" => $password);
            if (!file_exists($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/")) {
                mkdir($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/");
            }
            file_put_contents($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/$email.json", json_encode($credentials, JSON_PRETTY_PRINT));
        }
        else {
            echo "Passwords dont match.";
        }
    }
}
else {
    die("POST_REQUIRED");
}

function checkInput ($input) {
    $input = trim($input);
    $input = stripslashes($input);
    $input = htmlspecialchars($input);
    return $input;
}
?>
