const usernameField = document.querySelector("#usernameField");
const feedBackArea = document.querySelector(".invalid-feedback");

usernameField.addEventListener("keyup", (e) => {
  console.log("777777", 777777);

  const usernameval = e.target.value;

  usernameField.classList.remove("is-invalid");

  feedBackArea.style.display = "none";

  if (usernameval.length > 0) {
    fetch("/authentication/validate-username", {
      body: JSON.stringify({ username: usernameval }),
      method: "POST",
    })
      .then((res) => res.json())
      .then((data) => {
        console.log("data", data);
        if (data.username_error) {
          usernameField.classList.add("is-invalid");

          feedBackArea.style.display = "block";
          feedBackArea.innerHTML = `<p>${data.username_error}</p>`;
        }
      });
  }
});
