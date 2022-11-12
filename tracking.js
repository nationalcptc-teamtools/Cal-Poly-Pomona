function onEdit(event){
    if (event.source.getActiveSheet().getName().includes("Op ")) {
      var sheet = event.source.getActiveSheet();
      var a = event.source.getActiveRange();
      var index = a.getRowIndex();
      var column = a.getColumnIndex();
      var d = sheet.getRange(index,1);
      if (column == 5 && d.isBlank()) {
          var t = Utilities.formatDate(new Date(), "PST", "MMM dd, yyyy HH:mm:ss");
          d.setValue("'" + t);
      }
    }
  }