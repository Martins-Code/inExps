const usernameField = document.querySelector("#usernameField");
const feedBackArea = document.querySelector(".invalid-feedback");
const emailField = document.querySelector("#emailField");
const emailFeedBackArea = document.querySelector(".email-feedback");
const usernameSuccessOutput = document.querySelector(".usernameSuccessOutput");
const emailSuccessOutput = document.querySelector(".emailSuccessOutput");
const showPasswordToggle = document.querySelector(".showPasswordToggle");
const passwordField = document.querySelector("#passwordField");
const submitBtn = document.querySelector(".submit-btn");

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
                    submitBtn.disabled = true;
                    usernameField.classList.add("is-invalid");

                    feedBackArea.style.display = "block";
                    feedBackArea.innerHTML = `<p>${data.username_error}</p>`;
                } else {
                    submitBtn.removeAttribute("disabled")
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
                    submitBtn.disabled = true;
                    emailField.classList.add("is-invalid");

                    emailFeedBackArea.style.display = "block";
                    emailFeedBackArea.innerHTML = `<p>${data.email_error}</p>`;
                } else {
                    submitBtn.removeAttribute("disabled")
                }
            });
    }
})


const handleToggle = (e) => {
    if (showPasswordToggle.textContent === 'Show') {
        showPasswordToggle.textContent = 'Hide'

        passwordField.setAttribute("type", 'text')
    } else {
        showPasswordToggle.textContent = 'Show'


        passwordField.setAttribute("type", 'password')
    }
}
showPasswordToggle.addEventListener('click', handleToggle)