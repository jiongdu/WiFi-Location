package org.uestc.dujiong;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.mysql.jdbc.DatabaseMetaData;
import com.mysql.jdbc.ResultSetMetaData;

import java.util.ArrayList;
import java.text.SimpleDateFormat;

import org.apache.commons.math.optimization.direct.PowellOptimizer;
import org.apache.commons.math.stat.regression.SimpleRegression;
import org.omg.CORBA.INTERNAL;

public class WifiLocationGet {
	private static String DRIVER = "com.mysql.jdbc.Driver";
	private static String URL = "jdbc:mysql://localhost/wireless_info";
	private static String USERNAME = "root";
	private static String PASSWORD = "dujiong";
	private static int NUMAP = 3;
	private static double THRESHOLD = -65.0;
	//private static double A = -38; 		 //test in advance
	//private static double n = 2.50;		 //test in advance 
	private static double intercept=0;
	private static double slope=0;

	private static class Point{
		double x = 0;
		double y = 0;
		public Point(){
			this(0.0, 0.0);
		}
		public Point(Double x, Double y){
			this.x = x;
			this.y = y;
		}
		@Override
		public String toString(){
			return "(" + x + ", " + y + ")";
		}
	}
	/*
	 * Constructor
	 */
	public WifiLocationGet(){
		try {
			Class.forName(DRIVER).newInstance();
		}catch(Exception e){
		System.err.println("Exception:"+e.getMessage());
		}
	}
	
	/*
	 * Location Algorithm
	 * First, get the nearest AP from STA by RSSI
	 * Second, get the n from APs, Because the distance from AP to AP is known 
	 * Finally, get the STA location by difference method
	 */
	
    public static void main(String args[]) {
        Connection connection = null;
        try {
        	/*
        	 *  Set DateFormat
        	 */
        	SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-M-dd HH:mm:ss");
      
        	/*
        	 *  getConnection to MySQL
        	 */
        	connection = DriverManager.getConnection(URL,USERNAME,PASSWORD);
            if (!connection.isClosed()){
            	System.out.println("Successfully connected to MySQL!");
            }

            /*
             *  execute query to get data from MySQL between startTime to endTime(endTime+5)
             *  get the AP where rssi > threshold(-65dBm) and nearest AP from STA
             */
            
            String macaddrtest = new String("84:73:03:5f:46:91");
            String firstQuery = "select macaddr,nic_num,avg(rssi) as avg from sta_rssi "
            		+ "where macaddr = '84:73:03:5f:46:91'"
            		+ "and timestamp between '2016-07-29 22:09:20.657939' and '2016-07-29 22:09:33.756681' "
            		+ "group by macaddr,nic_num ORDER BY macaddr,avg(rssi) DESC";
            
            PreparedStatement preparedStatement = connection.prepareStatement(firstQuery);
            
            /*
        	String startTime = simpleDateFormat.format(new Date());
            preparedStatement.setString(1, startTime);
            
            Thread.sleep(5*1000);
            String endTime = simpleDateFormat.format(new Date());
            preparedStatement.setString(2, endTime);
           */
            ResultSet resultSet = preparedStatement.executeQuery();    
            
            double maxRssi = THRESHOLD;								 // the max Rssi that AP get from STA
            String maxRssiAp =new String("ap");					 // the relative nearest AP from STA
            List<Double> rssiArray = new ArrayList<>();		 // rssiArray: APn get the STA's rssi
           List<String> apArray = new ArrayList<>();      		 // the APs to caculate n
            HashMap<String, Double> hashMap = new HashMap<>();		//hashMap -> Key: nic_num of ap, Value: rssi of sta 
     
            while(resultSet.next()){
            	double rssi = resultSet.getDouble("avg");
            	if(rssi > THRESHOLD){
                	String nic_num = resultSet.getString("nic_num");
                	if(rssi > maxRssi){
                		maxRssi = rssi;
                		maxRssiAp = nic_num;
                	}
                	hashMap.put(nic_num, rssi);
                	System.out.print("nic_num  is "+ nic_num + "  ");
                	System.out.println("avg is " + rssi);
                	apArray.add(nic_num);
                   	rssiArray.add(rssi);
            	}	
            }
      		System.out.print("maxRssiAp is " + maxRssiAp + "  ");
    		System.out.println("maxRssi is " + maxRssi);
            
    	     /*
             * APn's Location
             */
            HashMap<String, Point> apLocation = new HashMap<>();
            apLocation.put(".1.196",new  Point(8.207,3.853));
            apLocation.put(".1.58", new Point(1.132,1.045));
            apLocation.put(".1.85",  new Point(1.483,8.574));
            apLocation.put(".1.86", new Point(8.955,9.124));
            
            /*
             * Calculate n
             */
            String secondQuery = "select nic_num, avg(rssi) from ap_rssi "
    				+ "where timestamp between '2016-07-29 22:09:00.379039' and '2016-07-29 22:09:03.876301' " //'2016-07-29 22:09:00.379039'
    				+ "and macaddr = (select mac from ap_location where nic_num =? ) group by nic_num";
    
            PreparedStatement pStatement = connection.prepareStatement(secondQuery);
    		pStatement.setString(1, maxRssiAp);
            ResultSet rs = pStatement.executeQuery();
    		List<Double> apAndApDistance = new ArrayList<>();
    		List<Double> apAndApRssi = new ArrayList<>(); 
    		int AP_NUM = rssiArray.size();					//STA->AP's,  number of rssi > THRESHOLD's AP
    		double[][] apAndApArray = new double[AP_NUM-1][2];  // calculate n  -> expression is (AP_NUM-1)
    		int k=0;
            while(rs.next()){
            	String apNum = rs.getString("nic_num");
            	if(apNum.equals(maxRssiAp)){
            		System.out.println("This is the maxRssiAp's own usb card" + apNum);
            	}else if(hashMap.containsKey(apNum)){
            		double avgRssi = rs.getDouble("avg(rssi)");
            		if(avgRssi > THRESHOLD){										//The same, rssi should be larger than THRESHOLD
            			double temp = Math.pow(apLocation.get(maxRssiAp).x-apLocation.get(apNum).x,2) +
            					Math.pow(apLocation.get(maxRssiAp).y-apLocation.get(apNum).y, 2);
            			double distance = Math.sqrt(temp);
            			apAndApDistance.add(distance);
            			apAndApRssi.add(avgRssi);
            			System.out.print("apNum is " + apNum + " ");
            			System.out.print("distance is " + distance +"  ");		//the other AP
            			System.out.println("avgRssi is " + avgRssi);				//the other get the maxRssiap's Rssi
            			apAndApArray[k][0] = -10 * (Math.log10(distance));		// y = intercept + slope * x, slope is n
            			apAndApArray[k][1] = avgRssi;												// Rssi = A + n * (-10logd)
            			k++;
            		}
            	}
            }
			SimpleRegression regression=new SimpleRegression();
            regression.addData(apAndApArray);
            intercept=regression.getIntercept();
            slope=regression.getSlope();
            System.out.println("A is " + intercept);		//intercept IS A
            System.out.println("n is " + slope);					//slope IS n
            
            /*
             *  遍历hashMap
             */
            /*
            Iterator iterator = hashMap.entrySet().iterator();
            while(iterator.hasNext()){
            	Map.Entry entry = (Map.Entry)iterator.next();
            	String Key = (String)entry.getKey();
            	System.out.print("Key is " + Key + " ");
                double Value = (Double)entry.getValue();
                System.out.println("Value is " + Value);
            }
          */
            /*
             * Differential to get the straight line or circle expression
             */
          int CAL_NUM = (AP_NUM * (AP_NUM-1))/2;
          double[][] apAndStaArray = new double[CAL_NUM][2];				// SimpleRegression()
          double[][] tempArray = new double[CAL_NUM][3];						// Used in transferring circle expression to straight liner expression
          int m=0;
          int n=0;
          for(int i=0; i<rssiArray.size(); i++){
        	  for(int j=i+1; j<rssiArray.size(); j++){
        		  double rssi1 = rssiArray.get(i);
        		  double rssi2 = rssiArray.get(j);
        		  double X1 = apLocation.get(apArray.get(i)).x;
        		  double Y1 = apLocation.get(apArray.get(i)).y;
        		  double X2 = apLocation.get(apArray.get(j)).x;
        		  double Y2 = apLocation.get(apArray.get(j)).y;
        		  double a = Math.pow(10, (rssi1-rssi2)/(10*slope));				// d2s / d1s
        		  Double distanceEqual = new Double(1.0);
        		  if(distanceEqual.equals(a)){							//the straight line expression: 	 2*(x1-x2)*X + 2*(y1-y2)*Y = x1^2+y1^2-x2^2-y2^2
        			  apAndStaArray[m][0] = (2*(Y1-Y2))/(2*(X1-X2));
        			  apAndStaArray[m][1] = (X1*X1+Y1*Y1-X2*X2-Y2*Y2)/(2*(X1-X2));
        			  m++;
        		  }else{																	//the expression is a circle  (x-m1)^2 + (y-n1)^2 = c1
        			   		tempArray[n][0] = (X2-X1*a*a)/(1-a*a);						//mi
        			   		tempArray[n][1] = (Y2-Y1*a*a)/(1-a*a);						//ni
        			   		tempArray[n][2] = ((Y1*Y1+X1*X1)*(a*a+a*a*a*a)-2*a*a*(X1*X2+Y1*Y2))/((1-a*a)*(1-a*a));    //ci
        			   		n++;																											 // m+n = n*(n-1) / 2
        		  }
        	  }
          }
          
          /*
           *  to circle expression, every minus the first expression and get a straight liner expression
           */
          for(int i=1;i<n;i++){
        	  apAndApArray[m][0] = (tempArray[0][1]-tempArray[i][1])/(tempArray[0][0]-tempArray[i][0]);
        	  double tempArrayTemp = tempArray[i][2]-tempArray[0][2]+tempArray[0][1]*tempArray[0][1]+tempArray[0][0]*tempArray[0][0]
        			  -tempArray[i][1]*tempArray[i][1]-tempArray[i][0]*tempArray[i][0];			//ci-c1+m1^2+n1^2-mi^2-ni^2
        	  apAndApArray[m][1] = tempArrayTemp/(2*(tempArray[0][0]-tempArray[i][0]));
        	  m++;
          }
          System.out.println("m is " + m);  //m=n-1, cause m is the number of circle, n is the liner expression(every minus the first circle expression ) 
      	 SimpleRegression regressionResult=new SimpleRegression();
         regressionResult.addData(apAndApArray);
         intercept=regressionResult.getIntercept();
         slope=regressionResult.getSlope();
         System.out.println("X is " + intercept);			//intercept IS X
         System.out.println("Y is " + slope);					//slope IS Y
            
          connection.close();     

        } catch(Exception e) {
            System.err.println("Exception: " + e.getMessage());
        }

    }   //end main
}
