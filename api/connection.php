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
        (isset($_POST["api_key"]) && !empty($_POST["api_key"]))) {

        //Username must not include any special characters and must be at least 5 characters long.
        $usernamePattern = "/^([a-zA-Z0-9]){5,20}$/";

        //API key must include only lowercase characters and numbers and be 64 characters long.
        $apiKeyPattern = "/^([a-z0-9]){64}$/";

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
        if (preg_match($apiKeyPattern, $_POST["api_key"])) {
            $apiKey = checkInput($_POST["api_key"]);
        }
        else {
            sendResponse("FAILURE",
                array(
                    "error" => "INVALID_API_KEY",
                    "message" => "Invalid API key."
                )
            );
            die();
        }

        if (isset($username) && isset($apiKey)) {

            if (accountExists($username)) {

                $jsonContent = json_decode(file_get_contents($_SERVER['DOCUMENT_ROOT'] . "/users/$username.json"), true);

                if (password_verify($apiKey, $jsonContent["apiKeyHash"])) {

                    foreach($jsonContent["computersInLocalNetwork"] as $key => $value) {

                        if (strcmp($jsonContent["computersInLocalNetwork"][$key]["wakeUp"], "true") == 0) {

                            $response[] = array("wakeUp" => $jsonContent["computersInLocalNetwork"][$key]["computerMac"]);

                            $jsonContent["computersInLocalNetwork"][$key]["wakeUp"] = "false";
                        }
                    }
                    file_put_contents($_SERVER['DOCUMENT_ROOT'] . "/users/$username.json", json_encode($jsonContent, JSON_PRETTY_PRINT), LOCK_EX);

                    if (isset($response)) {
                        sendResponse("SUCCESS", $response);
                    }
                    else {
                        sendResponse("SUCCESS",
                            array(
                                "message" => "NO_ACTION_REQUIRED"
                            )
                        );
                    }
                }
                else {
                    sendResponse("FAILURE",
                        array(
                            "error" => "INCORRECT_API_KEY",
                            "message" => "There is no account matching this authentication key."
                        )
                    );
                    die();
                }
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
        if (!isset($_POST["username"]) || !isset($_POST["api_key"])) {
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
