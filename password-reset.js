function requestPasswordReset(email) {
    fetch('http://localhost:4000/v1/tokens/password-reset', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: "duane@example.com" }), // Use dynamic email parameter
    })
    .then(response => response.json())
    .then(data => {
        console.log("Password reset email sent:", data.message);
    })
    .catch(error => {
        console.error("Error:", error);
    });
}
  
  // 2. Update password (PUT request)
  function updatePassword(token, newPassword) {
    fetch('http://localhost:4000/v1/users/password', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        token: token, // Reset token
        password: newPassword, // New password
      }),
    })
    .then(response => response.json())
    .then(data => {
      console.log("Password successfully reset:", data.message);
    })
    .catch(error => {
      console.error("Error:", error);
    });
  }
  
  // Example usage
  // Step 1: Request password reset (using your email)
  requestPasswordReset('duke@example.com');
  
  // Step 2: After getting the reset token from email, call this function
  // Example: updatePassword('your-reset-token-here', 'new-password123');
  