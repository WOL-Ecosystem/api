<?php
//Display errors if any
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

//Check if client connection is of type POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    //Check if POST data exists as variables and are not empty
    if ((isset($_POST["username"]) && !empty($_POST["username"])) &&
        (isset($_POST["password"]) && !empty($_POST["password"]))) {

        //Username must not include any special characters and must be at least 5 characters long.
        $usernamePattern = "/^([a-zA-Z0-9]){5,20}$/";
        //Password must include at least one uppercase and one lowercase characters, one number and one special character.
        $passwordPattern = "/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{9,32}$/";

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

        //Chech if the initialization of email, password and repeat_password comply.
        if (isset($username) && isset($password)) {

            //Check if the required directory exists. If does not exist, create it.
            if (!file_exists($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/")) {
                mkdir($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/");
            }

            //Check if account exists. If does not, create it.
            if (!accountExists($username)) {

                date_default_timezone_set('Europe/Athens');

                $passwordHash = hashInput($password);
                $apiKey = generateUniqueApiKey();
                $apiKeyHash = hashInput($apiKey);

                $credentials = array("username" => $username,
                                    "passwordHash" => $passwordHash,
                                    "apiKeyHash" => $apiKeyHash,
                                    "dateCreated" => date_format(date_create(), 'Y-m-d H:i:s'));

                //Export the credentials as json.
                file_put_contents($_SERVER['DOCUMENT_ROOT'] .
                    "/wols/userdata/$username.json", json_encode($credentials, JSON_PRETTY_PRINT));

                $serverResponse = array("API_KEY" => $apiKey);
                echo json_encode($serverResponse);
            }
            else {
                die("ACCOUNT_ALREADY_EXISTS");
            }
        }
    }
    //Handle missing post variables.
    else {
        if (!isset($_POST["username"]) || !isset($_POST["password"])) {
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

function generateUniqueApiKey () {
    return hash_hmac("sha512/256", bin2hex(random_bytes(1024)), bin2hex(random_bytes(1024)));
}

function accountExists ($username) {
    if (file_exists($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/$username.json")) {
        return true;
    }
    return false;
}
?>
