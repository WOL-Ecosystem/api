<?php
//Display errors if any
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

//Check if client connection is of type POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    //Check if POST data exists as variables and are not empty
    if ((isset($_POST["email"]) && !empty($_POST["email"])) &&
        (isset($_POST["password"]) && !empty($_POST["password"]))) {

        //Password must include at least one uppercase and one lowercase characters, one number and one special character.
        $passwordPattern = "/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{9,32}$/";

        //Check email and if is valid, save it. If email is invalid abort the connection.
        if (filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
            $email = $_POST["email"];
        }
        else {
            die("INVALID_EMAIL");
        }

        //Check password and if is valid, save it. If password is invalid abort the connection.
        if (preg_match($passwordPattern, $_POST["password"])) {
            $password = checkInput($_POST["password"]);
        }
        else {
            die("INVALID_PASSWORD");
        }

        //Chech if the initialization of email, password and repeat_password comply.
        if (isset($email) && isset($password)) {

            //Check if the required directory exists. If does not exist, create it.
            if (!file_exists($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/")) {
                mkdir($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/");
            }

            //Check if account exists. If does not, create it.
            if (!accountExists($email)) {

                date_default_timezone_set('Europe/Athens');

                $passwordHash = hashInput($password);
                $apiKey = hash_hmac("sha512", random_bytes(512), $passwordHash);
                $credentials = array("email" => $email,
                                    "passwordHash" => $passwordHash,
                                    "apiKey" => $apiKey,
                                    "dateCreated" => date_format(date_create(), 'Y-m-d H:i:s'));

                //Export the credentials as json.
                file_put_contents($_SERVER['DOCUMENT_ROOT'] .
                    "/wols/userdata/$email.json", json_encode($credentials, JSON_PRETTY_PRINT));

                echo $apiKey;
            }
            else {
                die("ACCOUNT_ALREADY_EXISTS");
            }
        }
    }
    //Handle missing post variables.
    else {
        if (!isset($_POST["email"]) || !isset($_POST["password"]) || !isset($_POST["repeat_password"])) {
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

function hashInput ($input) {
    $options = [
    'memory_cost' => 2048,
    'time_cost' => 4,
    'threads' =>3
    ];
    $inputHash = password_hash($input, PASSWORD_ARGON2I, $options);
    return $inputHash;
}

function accountExists ($email) {
    if (file_exists($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/$email.json")) {
        return true;
    }
    return false;
}
?>
