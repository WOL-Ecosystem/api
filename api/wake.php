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
        (isset($_POST["local_computer_names"]) && !empty($_POST["local_computer_names"]))) {

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

        //Check local computer name
        if (substr_count($_POST["local_computer_names"], ",")) {

            //Array local_computer_names separated with commas
            $localComputerNamesArray = explode(",", $_POST["local_computer_names"]);

            foreach ($localComputerNamesArray as $computerName) {

                $localComputerName = checkNames($computerName, $usernamePattern);

                //Array of the submited computers
                $namesOfLocalComputers[] = array("computerName" => $localComputerName);
            }
        }
        //only one computer was submited
        else {
            $localComputerName = checkNames($_POST["local_computer_names"], $usernamePattern);

            //Array of the submited computers
            $namesOfLocalComputers[] = array("computerName" => $localComputerName);
        }

        if (isset($username) && isset($password) && isset($namesOfLocalComputers)) {

            if (accountExists($username)) {

                $jsonContent = json_decode(file_get_contents($_SERVER['DOCUMENT_ROOT'] . "/users/$username.json"), true);

                $passwordHash = $jsonContent["passwordHash"];
                $apiKeyHash = $jsonContent["apiKeyHash"];

                if (password_verify($password, $passwordHash)) {

                    $nameDoesNotExistFlag = true;

                    foreach($jsonContent["computersInLocalNetwork"] as $key => $value) {

                        foreach($namesOfLocalComputers as $userInputNames) {

                            if (strcasecmp($jsonContent["computersInLocalNetwork"][$key]["computerName"], $userInputNames["computerName"]) == 0) {

                                if (strcmp($jsonContent["computersInLocalNetwork"][$key]["wakeUp"], "false") == 0) {
                                    $nameDoesNotExistFlag = false;

                                    $jsonContent["computersInLocalNetwork"][$key]["wakeUp"] = "true";

                                    echo "Your request to wake up " . $jsonContent["computersInLocalNetwork"][$key]["computerName"] . " was successfull. <br>";
                                }
                                else {
                                    $nameDoesNotExistFlag = false;
                                    echo "There is already a request to wake up '" . $jsonContent["computersInLocalNetwork"][$key]["computerName"] . "' <br>";
                                }
                            }
                        }
                    }
                    file_put_contents($_SERVER['DOCUMENT_ROOT'] . "/users/$username.json", json_encode($jsonContent, JSON_PRETTY_PRINT));//LOCK_EX
                    if ($nameDoesNotExistFlag == true) {
                        echo "The specified computer name(s) dont exist!";
                    }
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
        if (!isset($_POST["username"]) || !isset($_POST["password"]) || !isset($_POST["local_computer_names"])) {
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

function checkNames($localComputerName, $usernamePattern) {

    if (preg_match($usernamePattern, $localComputerName)) {
         return $localComputerName = checkInput($localComputerName);
    }
    else {
        die("INVALID_COMPUTER_NAME");
    }
}

function accountExists ($username) {
    if (file_exists($_SERVER['DOCUMENT_ROOT'] . "/users/$username.json")) {
        return true;
    }
    return false;
}
?>
