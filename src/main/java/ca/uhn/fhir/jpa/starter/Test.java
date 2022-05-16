package ca.uhn.fhir.jpa.starter;

import java.util.Calendar;
import java.util.Date;

public class Test {
	public static void main(String[] args) {
		Calendar nowCalendar = Calendar.getInstance();
		nowCalendar.setTimeInMillis(1652697306*1000L);
		System.out.println(nowCalendar.getTime().toString());
	}
}
