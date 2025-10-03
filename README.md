


# Log Auditor

## Requirements
- Java 21
- Python 3
- OpeanAI KEY

1. Java Scanner
```bash
 mvn clean install
 
 java -jar target/log-auditor-1.0-SNAPSHOT.jar {PATH_TO_YOUR_JAVA_SOURCE} > ./agent/logs.jsonl
 
```

2. Create an .env file in agent/ folder 
```txt
OPENAI_API_KEY={YOUR_OPEN_AI_KEY}
OPENAI_MODEL={YOUR_MODEL}
```

3. Log auditor agent
```bash
cd agent
pip install -r requirements.txt
python agent.py logs.jsonl
```