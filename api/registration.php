<?php
//Display errors if any
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

require_once $_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php';
//Check if client connection is of type POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    //Check if POST data exists as variables and are not empty
    if ((isset($_POST["username"]) && !empty($_POST["username"])) &&
        (isset($_POST["password"]) && !empty($_POST["password"])) &&
        (isset($_POST["mac_and_name"]) && !empty($_POST["mac_and_name"]))) {

        //Username must not include any special characters and must be at least 5 characters long.
        $usernamePattern = "/^([a-zA-Z0-9]){5,20}$/";

        //Password must include at least one uppercase and one lowercase characters, one number and one special character.
        $passwordPattern = "/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{9,32}$/";

        //Mac address must have 5 colons in between the characters.
        $macAddressPattern = "/^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/";

        //Check USERNAME and if is valid, save it. If email is invalid abort the connection.
        if (preg_match($usernamePattern, $_POST["username"])) {
            $username = checkInput($_POST["username"]);
        }
        else {
            sendResponse("FAILURE",
                array(
                    "error" => "INVALID_USERNAME",
                    "message" => "Invalid username."
                )
            );
            die();
        }

        //Check password and if is valid, save it. If password is invalid abort the connection.
        if (preg_match($passwordPattern, $_POST["password"])) {
            $password = checkInput($_POST["password"]);
        }
        else {
            sendResponse("FAILURE",
                array(
                    "error" => "INVALID_PASSWORD",
                    "message" => "Invalid password."
                )
            );
            die();
        }

        //Check local computer mac and name
        if (substr_count($_POST["mac_and_name"], ",")) {

            //Array of macs and names separated with commas
            $macAndNameArray = explode(",", $_POST["mac_and_name"]);

            foreach ($macAndNameArray as $localComputer) {

                //Mac and name of the current submited computer.
                $macAndName = explode(",", checkMacAndName($localComputer, $macAddressPattern, $usernamePattern));

                //Array of the submited computers
                $macAndNameOfLocalComputer[] = array("computerName" => $macAndName[1],
                                                    "computerMac" => $macAndName[0],
                                                    "wakeUp" => 'false');
            }
        }
        //only one computer was submited
        else {
            if (substr_count($_POST["mac_and_name"] , "-")) {
                //Mac and name of the submited computer
                $macAndName = explode(",", checkMacAndName($_POST["mac_and_name"], $macAddressPattern, $usernamePattern));

                //Array of the submited computers
                $macAndNameOfLocalComputer[] = array("computerName" => $macAndName[1],
                                                    "computerMac" => $macAndName[0],
                                                    "wakeUp" => 'false');
            }
            else {
                sendResponse("FAILURE",
                    array(
                        "error" => "INVALID_LOCAL_PC_ΝΑΜΕ_SYNTAX",
                        "message" => "Invalid syntax of the computer's mac and name. ex. 01:23:EC:67:89:AB-Hercules,0a:23:EC:67:89:AB-Cerberus"
                    )
                );
                die();
            }
        }


        //Chech if the initialization of email, password and repeat_password comply.
        if (isset($username) && isset($password) && isset($macAndNameOfLocalComputer)) {

            //Check if the required directory exists. If does not exist, create it.
            if (!file_exists($_SERVER['DOCUMENT_ROOT'] . "/users/")) {
                mkdir($_SERVER['DOCUMENT_ROOT'] . "/users/");
            }

            //Check if account exists. If does not, create it.
            if (!accountExists($username)) {

                date_default_timezone_set('Europe/Athens');

                $passwordHash = hashInput($password);
                $apiKey = generateUniqueApiKey($password);
                $apiKeyHash = hashInput($apiKey);

                $credentials = array("username" => $username,
                                    "passwordHash" => $passwordHash,
                                    "apiKeyHash" => $apiKeyHash,
                                    "computersInLocalNetwork" => $macAndNameOfLocalComputer,
                                    "dateCreated" => date_format(date_create(), 'Y-m-d H:i:s'));

                //Export the credentials as json.
                file_put_contents($_SERVER['DOCUMENT_ROOT'] .
                    "/users/$username.json", json_encode($credentials, JSON_PRETTY_PRINT));

                $serverResponse =
                sendResponse("SUCCESS",
                    array(
                        "API_KEY" => $apiKey
                    )
                );
            }
            else {
                sendResponse("FAILURE",
                    array(
                        "error" => "ACCOUNT_DOES_NOT_EXIST",
                        "message" => "There is no account matching this username."
                    )
                );
                die();
            }
        }
    }
    //Handle missing post variables.
    else {
        if (!isset($_POST["username"]) || !isset($_POST["password"]) || !isset($_POST["mac_and_name"])) {
            sendResponse("FAILURE",
                array(
                    "error" => "FORM_DATA_MISSING",
                    "message" => "Some required fields were not sent to the server."
                )
            );
            die();
        }
        else {
            sendResponse("FAILURE",
                array(
                    "error" => "FORM_DATA_EMPTY",
                    "message" => "Some required fields are not set."
                )
            );
            die();
        }
    }
}
else {
    sendResponse("FAILURE",
        array(
            "error" => "POST_REQUIRED",
            "message" => "Error while sending request. The request must be of type POST."
        )
    );
    die();
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

function checkMacAndName($localComputer, $macAddressPattern, $usernamePattern) {

    if (substr_count($localComputer , "-")) {
        $macAndNameOfLocalComputer =  explode("-", $localComputer);

        if (preg_match($macAddressPattern, $macAndNameOfLocalComputer[0])) {
            $computerMac = checkInput($macAndNameOfLocalComputer[0]);
        }
        else {
            sendResponse("FAILURE",
                array(
                    "error" => "INVALID_MAC_ADDRESS",
                    "message" => "Invalid MAC address."
                )
            );
            die();
        }

        if (preg_match($usernamePattern, $macAndNameOfLocalComputer[1])) {
            $computerName = checkInput($macAndNameOfLocalComputer[1]);
        }
        else {
            sendResponse("FAILURE",
                array(
                    "error" => "INVALID_COMPUTER_NAME",
                    "message" => "Invalid computer name."
                )
            );
            die();
        }
        return $computerMac. "," . $computerName;
    }
    else {
        sendResponse("FAILURE",
            array(
                "error" => "INVALID_LOCAL_PC_ΝΑΜΕ_SYNTAX",
                "message" => "Invalid syntax of the computer's mac and name. ex. 01:23:EC:67:89:AB-Hercules,0a:23:EC:67:89:AB-Cerberus"
            )
        );
        die();
    }
}

function generateUniqueApiKey ($password) {
    return hash_hmac("sha512/256", bin2hex(random_bytes(2048)), $password);
}

function accountExists ($username) {
    if (file_exists($_SERVER['DOCUMENT_ROOT'] . "/users/$username.json")) {
        return true;
    }
    return false;
}

function getApiVersion () {
    $client = new \Github\Client();
    $githubResponse = $client->api('repo')->releases()->latest('geocfu', 'WOL-Server');
    return $githubResponse["tag_name"];
}

function sendResponse ($status, $message) {
    $response = array(
        "apiVersion" => getApiVersion(),
        "status" => $status,
        "data" => $message
    );
    header('Content-Type: application/json');
    echo json_encode($response, JSON_PRETTY_PRINT);
}
?>
