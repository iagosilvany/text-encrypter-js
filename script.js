function handleEncrypt() {
    try {
        var key = document.getElementById('input_key').value.trim();
        if (key.toString().length !== 8) {
            throw new Error('Erro! A chave precisa ter 8 caracteres.');
        }
        var originalMsg = document.getElementById('input_original_msg').value.trim();
        var charsAndValues = initializeMatrix(key);
        var encryptedMessage = encryptMessage(originalMsg, charsAndValues.chars, charsAndValues.charsFaceValue);
        document.getElementById('resultado').innerHTML = "A mensagem criptografada é:\n" + encryptedMessage;
    } catch (error) {
        document.getElementById('error_text').innerHTML = error.message;
        
    }
}


function encryptMessage(message, chars, charsFaceValue) {

    var encryptedMessage = '';
    for (var i = 0; i < message.length; i++) {
        var char = message[i];
        if (char === ' ') {
            encryptedMessage += 'SPC';
        } else if (chars.includes(char)) {
            var index = chars.indexOf(char);
            encryptedMessage += charsFaceValue[index];
        }
    }
    return encryptedMessage;
}

function initializeMatrix(key) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-=_+[]{}|;:",.<>?/áàâãéèêíìóòôõúùüçÁÀÂÃÉÈÊÍÌÓÒÔÕÚÙÜÇ~0';
    var keyStr = key.toString();
    
    // Unpack the key digits
    var c1 = parseInt(keyStr[0]);
    var c2 = parseInt(keyStr[1]);
    var c3 = parseInt(keyStr[2]);
    var c4 = parseInt(keyStr[3]);
    var c5 = parseInt(keyStr[4]);
    var c6 = parseInt(keyStr[5]);
    var c7 = parseInt(keyStr[6]);
    var c8 = parseInt(keyStr[7]);
    
    // Calculate the new starting index for the character set
    var startIndex = (c1 + 1) * ((c2 + 2) + (c2 + 1) + (c3 + 1) / (c4 + 1 + c4 + 1) * (c5 + 1) + (c6 + 1) + (c7 + 1) * (c8 + 1));
    startIndex = parseInt(startIndex) % chars.length;
    
    // Roll (shift) the character set based on the new starting index
    var charsFaceValue = chars.slice(startIndex) + chars.slice(0, startIndex);
    
    return { chars: chars, charsFaceValue: charsFaceValue };
}

document.getElementById('encrypt_button').addEventListener("click", function(){
    handleEncrypt();
})



/*
def encrypt():
    try:
        key = int(key_entry.get())
        if len(str(key)) != 8:  # Updated to check for eight digits in the key
            raise ValueError
        message = input_text.get("1.0", tk.END).strip()
        chars, chars_face_value = initialize_matrix(key)
        encrypted_message = encrypt_message(message, chars, chars_face_value)
        output_text_widget.delete("1.0", tk.END)
        output_text_widget.insert(tk.END, f"Encrypted Message:\n{encrypted_message}")
        save_last_action("Encrypted", encrypted_message)
    except ValueError:
        messagebox.showerror("Error", "Invalid key. Please enter an eight-digit key.")

def encrypt_message(message, chars, chars_face_value):
    encrypted_message = ''
    for char in message:
        if char == ' ':
            encrypted_message += 'SPC'
        elif char in chars:
            index = chars.index(char)
            encrypted_message += chars_face_value[index]
    return encrypted_message

# Function to handle decryption
def decrypt():
    try:
        key = int(key_entry.get())
        if len(str(key)) != 8:  # Updated to check for eight digits in the key
            raise ValueError
        encrypted_message = input_text.get("1.0", tk.END).strip()
        chars, chars_face_value = initialize_matrix(key)
        decrypted_message = decrypt_message(encrypted_message, chars, chars_face_value)
        output_text_widget.delete("1.0", tk.END)
        output_text_widget.insert(tk.END, f"Decrypted Message:\n{decrypted_message}")
        save_last_action("Decrypted", decrypted_message)
    except ValueError:
        messagebox.showerror("Error", "Invalid key. Please enter an eight-digit key.")

# Function to decrypt a message
def decrypt_message(encrypted_message, chars, chars_face_value):
    decrypted_message = ''
    i = 0
    while i < len(encrypted_message):
        if encrypted_message[i:i+3] == 'SPC':
            decrypted_message += ' '
            i += 3
        elif encrypted_message[i] in chars_face_value:
            index = chars_face_value.index(encrypted_message[i])
            decrypted_message += chars[index]
            i += 1
    return decrypted_message

*/