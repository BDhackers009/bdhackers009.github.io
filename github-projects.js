import fetch from 'node-fetch';

const apiUrl = 'https://api.github.com/users/BDhaCkers009/repos'; // Update with your actual GitHub username
const token = process.env.PROJECTS_TOKEN; // Update to the correct environment variable name

fetch(apiUrl, {
    headers: {
        Authorization: `Bearer ${token}`,
    },
})
    .then(response => response.json())
    .then(data => {
        const projectsContainer = document.getElementById('projects-container');

        data.forEach(project => {
            const projectCard = document.createElement('div');
            projectCard.className = 'project-card p-6 rounded-md';
            projectCard.innerHTML = `
                <h3 class="text-xl mb-4">${project.name}</h3>
                <p class="text-gray-400 mb-4">${project.description || 'No description available.'}</p>
                <a href="${project.html_url}" class="text-green-500 hover:underline">View on GitHub</a>
            `;

            projectsContainer.appendChild(projectCard);
        });
    })
    .catch(error => console.error('Error fetching GitHub projects:', error));
