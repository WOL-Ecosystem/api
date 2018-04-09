<?php
//Display errors if any
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

//Check if client connection is of type POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    //Check if POST data exists as variables and are not empty
    if ((isset($_POST["email"]) && !empty($_POST["email"])) &&
        (isset($_POST["password"]) && !empty($_POST["password"])) &&
        (isset($_POST["local_pc_names"]) && !empty($_POST["local_pc_names"]))) {

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

        if (isset($email) && isset($password)) {

            if (accountExists($email)) {

                $jsonContent = json_decode(file_get_contents($_SERVER['DOCUMENT_ROOT'] . "/wols/userdata/$email.json"));

                $hash = $jsonContent->{"passwordHash"};

                if (password_verify($password, $hash)) {
                    echo "account is validated";
                    //handle local_pc_names variable
                }
                else {
                    die("INCORRECT_PASSWORD");
                }
            }
            else {
                die("ACCOUNT_DOES_NOT_EXIST");
            }
        }
    }
    //Handle missing post variables.
    else {
        if (!isset($_POST["email"]) || !isset($_POST["password"]) || !isset($_POST["local_pc_names"])) {
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
