using Konscious.Security.Cryptography;
using System.Text;

// function used to decode base64 without padding into bytes 
byte[] decodeBase64(String input)
{
    // add missing padding if neccessary
    input = input.PadRight(input.Length + (4 - input.Length % 4), '=');

    // standard converstion base64 -> bytes
    return Convert.FromBase64String(input);
}

// encoded Argon2id hash, these are stored in database
var originalHash = "$argon2id$v=19$m=65536,t=4,p=1$1qNJ0hTZto3OfkUG9Avd3w$EGzeNrJOV7Jp71DcXvWU3emgvHSbqom4usLNXL7m9e0";

// split encoded hash using $ separator
var splittedOriginalHash = originalHash.Split('$');

// first two fields - algorithm and version, these are not relevant
var algorithm = splittedOriginalHash[1];
var version = splittedOriginalHash[2];

// third field - Argon2id`s settings - m (memory cost), t (time cost / interations), p (lanes / parallelism)
var settings = splittedOriginalHash[3].Split(',');

// parse settings values into integers
var memoryCost = Int32.Parse(settings[0].Split('=')[1]);
var iterations = Int32.Parse(settings[1].Split('=')[1]);
var parallelism = Int32.Parse(settings[2].Split('=')[1]);

// fourth field - unpadded base64 salt
var salt = splittedOriginalHash[4];

// fifth field - unpadded base64 hash
var hash = splittedOriginalHash[5];

// password inputted by user in login form
var passwordInput = "pass";

// convert inputted password to bytes using UTF-8
var passwordInputBytes = Encoding.UTF8.GetBytes(passwordInput);

// hash password input using Argon2id
var argon2 = new Argon2id(passwordInputBytes);

// set hashing settings and salt
argon2.DegreeOfParallelism = parallelism;
argon2.Iterations = iterations;
argon2.MemorySize = memoryCost;
argon2.Salt = decodeBase64(salt);

// decode encoded hash into bytes
var decodedHash = decodeBase64(hash);

// get the same amount of bytes from argon2 as in decoded hash
var generatedHash = argon2.GetBytes(decodedHash.Length);

// compare bytes sequences between decoded and generated hashes
if (generatedHash.SequenceEqual(decodedHash))
{
    Console.WriteLine("User login successful");
}
else
{
    Console.WriteLine("Password mismatch");
};