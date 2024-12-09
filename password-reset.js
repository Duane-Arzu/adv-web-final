fetch("http://localhost:4000/api/v1/tokens/authentication", {
    method: "POST",
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email: 'duane@example.com',
      password: 'yousayless'
    })
  })
  .then(function(response) {
    response.text().then(function(text) {
      console.log("Response:", text);
    });
  }, function(err) {
    console.error("Error:", err);
  });