<?php
//Display errors if any
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

//Check if client connection is of type POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    //Check if POST data exists as variables and are not empty
    if ((isset($_POST["username"]) && !empty($_POST["username"])) &&
        (isset($_POST["password"]) && !empty($_POST["password"])) &&
        (isset($_POST["api_key"]) && !empty($_POST["api_key"]))) {

        //Username must not include any special characters and must be at least 5 characters long.
        $usernamePattern = "/^([a-zA-Z0-9]){5,20}$/";

        //Password must include at least one uppercase and one lowercase characters, one number and one special character.
        $passwordPattern = "/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{9,32}$/";

        //API key must include only lowercase characters and numbers and be 64 characters long.
        $apiKeyPattern = "/^([a-z0-9]){64}$/";

        //Check USERNAME and if is valid, save it. If email is invalid abort the connection.
        if (preg_match($usernamePattern, $_POST["username"])) {
            $username = checkInput($_POST["username"]);
        }
        else {
            die("INVALID_USERNAME");
        }

        //Check password and if is valid, save it. If password is invalid abort the connection.
        if (preg_match($passwordPattern, $_POST["password"])) {
            $password = checkInput($_POST["password"]);
        }
        else {
            die("INVALID_PASSWORD");
        }

        //Check password and if is valid, save it. If password is invalid abort the connection.
        if (preg_match($apiKeyPattern, $_POST["api_key"])) {
            $apiKey = checkInput($_POST["api_key"]);
        }
        else {
            die("INVALID_API_KEY");
        }

        if (isset($username) && isset($password) && isset($apiKey)) {

            if (accountExists($username)) {

                $jsonContent = json_decode(file_get_contents($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/$username.json"));

                $passwordHash = $jsonContent->{"passwordHash"};
                $apiKeyHash = $jsonContent->{"apiKeyHash"};

                if (password_verify($password, $passwordHash) && password_verify($apiKey, $apiKeyHash)) {
                    unlink($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/$username.json");
                    echo "Account: $username, has been succefully removed!";
                }
                else {
                    die("INCORRECT_PASSWORD_OR_API_KEY");
                }
            }
            else {
                die("ACCOUNT_DOES_NOT_EXIST");
            }
        }
    }
    //Handle missing post variables.
    else {
        if (!isset($_POST["username"]) || !isset($_POST["password"]) || !isset($_POST["api_key"])) {
            die("FORM_DATA_MISSING");
        }
        else {
            die("FORM_DATA_EMPTY");
        }
    }
}
else {
    die("POST_REQUIRED");
}

function checkInput ($input) {
    $input = trim($input);
    $input = htmlspecialchars($input);
    return $input;
}

function accountExists ($username) {
    if (file_exists($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/$username.json")) {
        return true;
    }
    return false;
}
?>
