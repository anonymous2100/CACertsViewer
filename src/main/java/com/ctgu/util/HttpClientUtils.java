package com.ctgu.util;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.*;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author lihuahui
 * @version 1.0
 * @description:
 * @date 2026-04-20 09:02
 */
public class HttpClientUtils
{
  /**
   * 连接建立超时时间(单位:毫秒)
   */
  private static final int CONNECT_TIMEOUT = 5000;
  /**
   * 数据传输超时时间(单位:毫秒)
   */
  private static final int SOCKET_TIMEOUT = 10000;

  /**
   * 执行GET请求
   *
   * @param url     请求地址
   * @param headers 请求头
   * @return 响应内容字符串
   */
  public static String doGet(String url, Map<String, String> headers) throws IOException
  {
    HttpGet httpGet = new HttpGet(url);
    // 设置请求头
    setHeaders(httpGet, headers);
    return executeRequest(httpGet);
  }

  /**
   * 执行GET请求
   *
   * @param url     请求地址
   * @param headers 请求头
   * @param params  请求参数
   * @return 响应内容字符串
   */
  public static String doGet(String url, Map<String, String> headers, Map<String, String> params) throws IOException, URISyntaxException
  {
    URIBuilder uriBuilder = new URIBuilder(url);
    // 设置请求参数
    if(params != null && !params.isEmpty())
    {
      for(Map.Entry<String, String> entry : params.entrySet())
      {
        uriBuilder.setParameter(entry.getKey(), entry.getValue());
      }
    }
    HttpGet httpGet = new HttpGet(uriBuilder.build());
    // 设置请求头
    setHeaders(httpGet, headers);
    return executeRequest(httpGet);
  }

  /**
   * 执行POST请求(表单方式)
   *
   * @param url 请求地址
   * @return 响应内容字符串
   */
  public static String doPost(String url) throws IOException
  {
    return doPost(url, null, null);
  }

  /**
   * 执行POST请求(表单方式)
   *
   * @param url     请求地址
   * @param headers 请求头
   * @return 响应内容字符串
   */
  public static String doPost(String url, Map<String, String> headers) throws IOException
  {
    return doPost(url, headers, null);
  }

  /**
   * 执行POST请求(表单方式)
   *
   * @param url     请求地址
   * @param headers 请求头
   * @param params  请求参数
   * @return 响应内容字符串
   */
  public static String doPost(String url, Map<String, String> headers, Map<String, String> params) throws IOException
  {
    HttpPost httpPost = new HttpPost(url);
    // 设置请求头
    setHeaders(httpPost, headers);
    // 构建表单参数
    if(params != null)
    {
      List<NameValuePair> paramList = new ArrayList<>();
      for(Map.Entry<String, String> entry : params.entrySet())
      {
        paramList.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
      }
      httpPost.setEntity(new UrlEncodedFormEntity(paramList, StandardCharsets.UTF_8));
    }
    return executeRequest(httpPost);
  }

  /**
   * 执行POST请求(JSON格式)
   *
   * @param url     请求地址
   * @param headers 请求头
   * @return 响应内容字符串
   */
  public static String doPostJson(String url, Map<String, String> headers) throws IOException
  {
    return doPostJson(url, headers, null);
  }

  /**
   * 执行POST请求(JSON格式)
   *
   * @param url      请求地址
   * @param headers  请求头
   * @param jsonBody JSON请求体字符串
   * @return 响应内容字符串
   */
  public static String doPostJson(String url, Map<String, String> headers, String jsonBody) throws IOException
  {
    HttpPost httpPost = new HttpPost(url);
    // 添加JSON请求头
    addJsonHeader(httpPost, headers);
    // 添加自定义请求头
    setHeaders(httpPost, headers);
    // 设置JSON请求体
    if(jsonBody != null)
    {
      StringEntity entity = new StringEntity(jsonBody, ContentType.APPLICATION_JSON.withCharset(StandardCharsets.UTF_8));
      httpPost.setEntity(entity);
    }
    return executeRequest(httpPost);
  }

  /**
   * 执行PUT请求(JSON格式)
   *
   * @param url      请求地址
   * @param headers  请求头
   * @param jsonBody JSON请求体字符串
   * @return 响应内容字符串
   */
  public static String doPut(String url, Map<String, String> headers, String jsonBody) throws IOException
  {
    HttpPut httpPut = new HttpPut(url);
    // 添加JSON请求头
    addJsonHeader(httpPut, headers);
    // 添加自定义请求头
    setHeaders(httpPut, headers);
    // 设置JSON请求体
    if(jsonBody != null)
    {
      StringEntity entity = new StringEntity(jsonBody, ContentType.APPLICATION_JSON.withCharset(StandardCharsets.UTF_8));
      httpPut.setEntity(entity);
    }
    return executeRequest(httpPut);
  }

  /**
   * 执行DELETE请求
   *
   * @param url     请求地址
   * @param headers 请求头
   * @return 响应内容字符串
   */
  public static String doDelete(String url, Map<String, String> headers) throws IOException
  {
    HttpDelete httpDelete = new HttpDelete(url);
    // 设置请求头
    setHeaders(httpDelete, headers);
    return executeRequest(httpDelete);
  }

  /**
   * 创建带超时配置的HttpClient
   *
   * @return HttpClient实例
   */
  private static CloseableHttpClient createHttpClient()
  {
    RequestConfig requestConfig = RequestConfig.custom().setConnectTimeout(CONNECT_TIMEOUT).setSocketTimeout(SOCKET_TIMEOUT).build();
    return HttpClients.custom().setDefaultRequestConfig(requestConfig).build();
  }

  /**
   * 添加JSON请求头
   *
   * @param httpRequest HTTP请求对象
   * @param headers     请求头
   */
  private static void addJsonHeader(HttpRequestBase httpRequest, Map<String, String> headers)
  {
    if(headers == null || !headers.containsKey("Content-Type"))
    {
      httpRequest.addHeader("Content-Type", "application/json;charset=utf-8");
    }
  }

  /**
   * 设置请求头
   *
   * @param httpRequest HTTP请求对象
   * @param headers     请求头
   */
  private static void setHeaders(HttpRequestBase httpRequest, Map<String, String> headers)
  {
    if(headers == null || headers.isEmpty())
    {
      return;
    }
    for(Map.Entry<String, String> entry : headers.entrySet())
    {
      httpRequest.setHeader(entry.getKey(), entry.getValue());
    }
  }

  /**
   * 统一执行请求并处理响应
   *
   * @param httpRequest HTTP请求对象
   * @return 响应内容字符串
   */
  private static String executeRequest(HttpRequestBase httpRequest) throws IOException
  {
    try (CloseableHttpClient httpClient = createHttpClient())
    {
      try (CloseableHttpResponse response = httpClient.execute(httpRequest))
      {
        return handleResponse(response);
      }
    }
  }

  /**
   * 处理响应结果
   *
   * @param response HTTP响应对象
   * @return 响应内容字符串
   */
  private static String handleResponse(CloseableHttpResponse response) throws IOException
  {
    int statusCode = response.getStatusLine().getStatusCode();
    if(statusCode != HttpStatus.SC_OK)
    {
      throw new RuntimeException("HTTP请求失败，状态码：" + statusCode);
    }
    HttpEntity entity = response.getEntity();
    if(entity != null)
    {
      return EntityUtils.toString(entity, StandardCharsets.UTF_8);
    }
    return null;
  }
}
