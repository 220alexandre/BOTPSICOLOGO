document.addEventListener("DOMContentLoaded", function () {
  document.getElementById("sendButton").addEventListener("click", sendMessage);
});

async function sendMessage(event) {
  event.preventDefault(); // Prevenir a submissão do formulário
  const userInput = document.getElementById("userInput").value;
  const messagesDiv = document.getElementById("messages");
  const csrfToken = document.querySelector('input[name="csrf_token"]').value;

  // Exibindo a mensagem do usuário
  const userMessageDiv = document.createElement("div");
  userMessageDiv.textContent = `Você: ${userInput}`;
  messagesDiv.appendChild(userMessageDiv);

  // Enviando a mensagem para o backend
  const response = await fetch("/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": csrfToken,
    },
    body: JSON.stringify({ message: userInput }),
  });

  const data = await response.json();

  if (data.error) {
    alert(data.error);
  } else {
    // Exibindo a resposta do bot
    const botMessageDiv = document.createElement("div");
    botMessageDiv.textContent = `Bot: ${data.response}`;
    messagesDiv.appendChild(botMessageDiv);

    // Limpando o campo de entrada
    document.getElementById("userInput").value = "";

    // Rolando para a última mensagem
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
  }
}
