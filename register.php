<?php
//Display the errors
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    //Check if POST data exists as variables and are not empty
    if ((isset($_POST["email"]) && !empty($_POST["email"])) &&
        (isset($_POST["password"]) && !empty($_POST["password"])) &&
        (isset($_POST["repeat_password"]) && !empty($_POST["repeat_password"]))) {

        //Password must include at least one uppercase and one lowercase characters, one number and one special charachter
        $passwordPattern = "/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{8,32}$/";

        //mail
        if (filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
            $email = checkInput($_POST["email"]);
            $emailState = "VALID";
        }
        else {
            $emailState = "INVALID";
        }
        //password
        if (preg_match($passwordPattern, $_POST["password"])) {
            $password = checkInput($_POST["password"]);
            $passwordState = "VALID";
        }
        else {
            $passwordState = "INVALID";
        }
        //repeat_password
        if (preg_match($passwordPattern, $_POST["repeat_password"])) {
            $repeat_password = checkInput($_POST["repeat_password"]);
            $repeatPasswordState = "VALID";
        }
        else {
            $repeatPasswordState = "INVALID";
        }

        //Chech if password and repeat_password are valid and match
        if (strcmp(strcmp($passwordState, $repeatPasswordState), "VALID") == 0) {
            $credentials = array("email" => $email,
                                "password" => $password);

            if (!file_exists($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/")) {
                mkdir($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/");
            }
            file_put_contents($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/$email.json", json_encode($credentials, JSON_PRETTY_PRINT));

            $passwordMatchState = true;

            $serverState = "SUCCESS";
        }
        else {
            $passwordMatchState = false;
            $serverState = "FAILURE";
        }

        $serverResponse = array("Email" => $emailState,
                                "Password" => $passwordState,
                                "Repeat_Password" => $repeatPasswordState,
                                "Passwords Match" => $passwordMatchState,
                                "Server Response" => $serverState);

        $jsonServerResponse = json_encode($serverResponse);
        echo $jsonServerResponse;
    }
    else {
        if (!isset($_POST["email"]) || !isset($_POST["password"]) || !isset($_POST["repeat_password"])) {
            die("FORM_DATA_MISSING");
        }
        elseif (empty($_POST["email"]) || empty($_POST["password"]) || empty($_POST["repeat_password"])) {
            die("FORM_DATA_EMPTY");
        }
    }
}
else {
    echo "POST_REQUIRED";
    die();
}

function checkInput ($input) {
    $input = trim($input);
    $input = stripslashes($input);
    $input = htmlspecialchars($input);
    return $input;
}
?>
