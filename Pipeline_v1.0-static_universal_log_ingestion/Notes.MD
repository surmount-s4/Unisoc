For Adding sources to the pipeline:
  
    In the source-side-log-parser.py:

      search for payload --> for source put the name of the source of that logger

    In the reciever.py :
      add the name to this list 
      ALLOWED_SOURCES = ["Source1", "Source2", "Source3"]


The reciever.py is handled for common schema of logs coming from windows machines, yet to handle schema for other devices such as firewalls, HMI's, PLC's (only if needed)


Make the source_sided scripts into a SERIVCE so as to run continously 

Also how can we make the pipeline secure and make sure cover all endpoints


We will be needing different queues in RabbitMq if we want to process certain logs differently such as direct llm proccessing of mysterious commands and anything else if needed or maybe dashboard send and DB store simultaneously


# Filepath to the CSV file
csv_file = "C:\\ProgramData\\CustomSecurityLogs\\CUSTOM_LOGGERS\\SecurityEvents.csv"

# Add mac address as source 

FOR SCADA:

check timestamp compatiblity from the beginning as the columns are different



i want to make some changes on how you would be using data from the 1st pass to llm , i want you the check the table in the db (details mentioned in the watcher.py file) to filter out warning or critical based alerts from severity column 