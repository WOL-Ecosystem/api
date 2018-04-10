<?php
//Display errors if any
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

//Check if client connection is of type POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    //Check if POST data exists as variables and are not empty
    if ((isset($_POST["email"]) && !empty($_POST["email"])) &&
        (isset($_POST["auth_key"]) && !empty($_POST["auth_key"])) &&
        (isset($_POST["local_pc_names"]) && !empty($_POST["local_pc_names"]))) {

        //Password must include at least one uppercase and one lowercase characters, one number and one special character.
        $passwordPattern = "/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{9,32}$/";
        $apiKeyPattern = "/^([a-f0-9]){128}$/";

        //Check email and if is valid, save it. If email is invalid abort the connection.
        if (filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
            $email = $_POST["email"];
        }
        else {
            die("INVALID_EMAIL");
        }

        //Check password and if is valid, save it. If password is invalid abort the connection.
        if (preg_match($passwordPattern, $_POST["auth_key"])) {
            $auth_key = checkInput($_POST["auth_key"]);
        }
        elseif (preg_match($apiKeyPattern, $_POST["auth_key"])) {
            $auth_key = checkInput($_POST["auth_key"]);
        }
        else {
            die("INVALID_AUTH_KEY");
        }

        if (isset($email) && isset($auth_key)) {

            if (accountExists($email)) {

                $jsonContent = json_decode(file_get_contents($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/$email.json"));

                $passwordHash = $jsonContent->{"passwordHash"};
                $apiKey = $jsonContent->{"apiKey"};

                if (password_verify($auth_key, $passwordHash)) {
                    echo "account is validated by password";
                }
                elseif (hash_equals($auth_key, $apiKey)) {
                    echo "account is validated by apiKey";
                }
                else {
                    die("INCORRECT_AUTH_KEY");
                }
            }
            else {
                die("ACCOUNT_DOES_NOT_EXIST");
            }
        }
    }
    //Handle missing post variables.
    else {
        if (!isset($_POST["email"]) || !isset($_POST["auth_key"]) || !isset($_POST["local_pc_names"])) {
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

function accountExists ($email) {
    if (file_exists($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/$email.json")) {
        return true;
    }
    return false;
}
?>
