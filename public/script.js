document.addEventListener("click", function (event) {
    // Show emoji picker when the "plus" icon is clicked
    if (event.target.classList.contains("reaction-btn")) {
        const messageId = event.target.getAttribute("data-message-id");
        const emojiPicker = document.getElementById(`emoji-picker-${messageId}`);
            
            if (emojiPicker) {
                emojiPicker.style.display = (emojiPicker.style.display === "none" || emojiPicker.style.display === "") ? "block" : "none";
            }
        }
    });

    // Use event delegation to handle emoji clicks dynamically
    document.body.addEventListener("click", function (event) {
        if (event.target.classList.contains("emoji-image")) {
            const emoji = event.target.getAttribute("data-emoji");
            const messageContainer = event.target.closest(".message-container");
            if (!messageContainer) return;

            const messageId = messageContainer.querySelector(".reaction-btn").getAttribute("data-message-id");
            addReaction(messageId, emoji);
        }
    });


function addReaction(messageId, emoji) {
    fetch(`/addReaction/${messageId}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ emoji: emoji }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Find the correct reactions div inside the message
            const messageContainer = document.querySelector(`.reaction-btn[data-message-id="${messageId}"]`).closest(".message-container");
            const reactionsDiv = messageContainer.querySelector(".reactions");

            // Append the new emoji
            reactionsDiv.innerHTML += `<img src="/public/emojis/${emoji}.png" class="emoji-image" alt="${emoji}">`;

            // Hide emoji picker after selection
            const emojiPicker = document.getElementById(`emoji-picker-${messageId}`);
            if (emojiPicker) {
                emojiPicker.style.display = "none";
            }
        }
    })
    .catch(error => {
        console.error("Error adding reaction:", error);
    });
}
