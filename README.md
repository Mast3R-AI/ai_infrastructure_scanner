# Python scanner for AI infrastructure recognition

This project was made using my own programming knowledge and Cursor AI.

-----

#### The main issue was that the project gets messy and to complicated over time.
When building the very first version of that program I haven't defined the architecture on my own. I specified the Cursor AI what functionality of the scanner I need. I only made a detailed explanation of features, requirements and possibilities. I completely ignored the architecture side. This quickly lead the project to become to complicated and poorly working.
My problem was that I was expecting the Cursor to solve every problem for me. I didn't understand that Cursor is an assistant. This AI is only converting my ideas into real programmed algorithm but it cannot make an infrastructure on it's own.

The second time I starded from the ground and planned the whole architecture myself. I drawed all the schemes, all the planned features and every component. Then I formulated the foldeers structure and how to group the algorithms. Finally I elaborated the first prompt. It took me a while and it was very precise. I defined the folder and file structure, I made a standard for data files and whole hierarchy.

The idea is that there are 3 main folders:
1. The data folder: there are all .yaml files that contain the characteristics about AI services. For example we know that Ollama returns word "models" in json response. There are lots of indicators including http headers, json files and error handling.
2. The gathering folder: in this folder there are all algorithms for gaining information from target. In order to minimise the amount of noise we generate, the tool conducts tests for a specific software from the hierarchy haystack. Scanner is taking the first service and checks the tests. When it is not successful then scanner goes to the next candidate.
3. The matching folder: there are all algorithms needed to state what service we are dealing and how to format the output.

