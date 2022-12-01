const usernameField = document.querySelector("#usernameField");
const feedBackArea = document.querySelector(".invalid-feedback");
const emailField = document.querySelector("#emailField");
const emailFeedBackArea = document.querySelector(".email-feedback");
const usernameSuccessOutput = document.querySelector(".usernameSuccessOutput");
const emailSuccessOutput = document.querySelector(".emailSuccessOutput");

usernameField.addEventListener("keyup", (e) => {

    const usernameval = e.target.value;

    usernameSuccessOutput.style.display = "block";

    usernameSuccessOutput.textContent = `Checking ${usernameval}`

    usernameField.classList.remove("is-invalid");

    feedBackArea.style.display = "none";

    if (usernameval.length > 0) {
        fetch("/authentication/validate-username", {
            body: JSON.stringify({username: usernameval}), method: "POST",
        })
            .then((res) => res.json())
            .then((data) => {
                console.log("data", data);
                usernameSuccessOutput.style.display = "none";
                if (data.username_error) {
                    usernameField.classList.add("is-invalid");

                    feedBackArea.style.display = "block";
                    feedBackArea.innerHTML = `<p>${data.username_error}</p>`;
                }
            });
    }
});


emailField.addEventListener("keyup", (e) => {
    const emailval = e.target.value;

    emailSuccessOutput.style.display = "block";

    emailSuccessOutput.textContent = `Checking ${emailval}`

    emailField.classList.remove("is-invalid");

    emailFeedBackArea.style.display = "none";

    if (emailval.length > 0) {
        fetch("/authentication/validate-email", {
            body: JSON.stringify({email: emailval}), method: "POST",
        })
            .then((res) => res.json())
            .then((data) => {
                console.log("data", data);

                emailSuccessOutput.style.display = "none";

                if (data.email_error) {
                    emailField.classList.add("is-invalid");

                    emailFeedBackArea.style.display = "block";
                    emailFeedBackArea.innerHTML = `<p>${data.email_error}</p>`;
                }
            });
    }
})